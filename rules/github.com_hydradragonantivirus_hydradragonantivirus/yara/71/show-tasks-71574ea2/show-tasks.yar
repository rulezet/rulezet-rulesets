rule show_tasks {
  meta:
    description = "amadey-botnet - file show_tasks.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "8a9bbd5e499be6a536df5704319bac256b900ca2902a9c9b3b5f51735506b1ad"

  strings:
    $s1  = "echo \"SQL connection filed, check host, name, login and password\";" fullword ascii
    $s2  = "header( \"Location: login.php\" );" fullword ascii
    $s3  = "if ( @mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ) == false )" fullword ascii
    $s4  = "echo \"<td bgcolor = \" . $gb . \">\" . \"<img src=\\\"images\\ic_2.png\\\"> \" . $filetype . \"</td>\";" fullword ascii
    $s5  = "<td><div align = center>Download errors:</div></td> " fullword ascii
    $s6  = "\"  \" . \"<a href=\\\"del_task.php?id=\" . $id . \"\\\">[delete]</a> \" . \"</div></td>\";" fullword ascii
    $s7  = "$result = mysql_query( \"SELECT * FROM tasks ORDER BY id DESC\" );" fullword ascii
    $s8  = "<a href=\\\"make_task.php\\\"><img src=\\\"images\\ic_5.png\\\"> Add task</a>" fullword ascii
    $s9  = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $progress . \"%\" . \"</div></td>\";" fullword ascii
    $s10 = "include( \"header.php\" );" fullword ascii
    $s11 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $success . \"%\" . \"</div></td>\";" fullword ascii
    $s12 = "$good = $row['exec'];" fullword ascii
    $s13 = "echo \"<td bgcolor = \" . $gb . \">\" . $autorun . \"</td>\";" fullword ascii
    $s14 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $good . \"</div></td>\";" fullword ascii
    $s15 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $l_err . \"</div></td>\";" fullword ascii
    $s16 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $d_err . \"</div></td>\";" fullword ascii
    $s17 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $needs . \"</div></td>\";" fullword ascii
    $s18 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $units . \"</div></td>\";" fullword ascii
    $s19 = "echo \"<td bgcolor = \" . $gb . \"><div align = center>\" . $done . \"</div></td>\";" fullword ascii
    $s20 = "<table border=\\\"0\\\" width=\\\"1200\\\" cellspacing=\\\"0\\\" cellpadding=\\\"0\\\">" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (8 of them)
    ) or (all of them)
}