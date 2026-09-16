rule statistic {
  meta:
    description = "amadey-botnet - file statistic.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "f64f7d52d4c08cc089f5f723de1489a247c9d5dd08f81da8d0b82cb63b31c4eb"

  strings:
    $s1  = "echo \"SQL connection filed, check host, name, login and password\";" fullword ascii
    $s2  = "echo \"<tr><td bgcolor = \". $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"Units online:\" . \"</td>\"; " fullword ascii
    $s3  = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"Active tasks:\" . \"</td>\"; " fullword ascii
    $s4  = "echo \"<td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"New units on day:\" . \"</td>\"; " fullword ascii
    $s5  = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"Units:\" . \"</td>\"; " fullword ascii
    $s6  = "echo \"<tr><td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . \"Loads:\" . \"</td>\"; " fullword ascii
    $s7  = "header( \"Location: login.php\" );" fullword ascii
    $s8  = "if ( @mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ) == false )" fullword ascii
    $s9  = "$result = mysql_query( 'SELECT * FROM units WHERE reg >' . ( time() - 86400 ) );" fullword ascii
    $s10 = "$result = mysql_query( 'SELECT * FROM units WHERE online > ' . ( time() - 604800 ) );" fullword ascii
    $s11 = "$result = mysql_query( 'SELECT * FROM units WHERE online > ' . ( time() - 60 ) );" fullword ascii
    $s12 = "$result =  mysql_query( 'SELECT * FROM units WHERE online > ' . ( time() - 86400 ) );" fullword ascii
    $s13 = "$result = mysql_query( 'SELECT * FROM units WHERE reg > ' . ( time() - 604800 ) );" fullword ascii
    $s14 = "mysql_connect( $conf[\"dbhost\"], $conf[\"dbuser\"], $conf[\"dbpass\"] );" fullword ascii
    $s15 = "$percent = aVersionUnitsCount( $row['version'] ) / ( GetUnitsCount() / 100 );" fullword ascii
    $s16 = "$result = mysql_query( 'SELECT * FROM units WHERE version = \"' . $version . '\"' );" fullword ascii
    $s17 = "echo \"   <td bgcolor = \" . $gb . \">\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\">&nbsp;\" . $row['version'] . \"</td>\"; " fullword ascii
    $s18 = "$res = mysql_query( \"SELECT SUM( error + error2 ) AS sum FROM tasks\" ); " fullword ascii
    $s19 = "@mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] );" fullword ascii
    $s20 = "mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] );" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 50KB and
      (8 of them)
    ) or (all of them)
}