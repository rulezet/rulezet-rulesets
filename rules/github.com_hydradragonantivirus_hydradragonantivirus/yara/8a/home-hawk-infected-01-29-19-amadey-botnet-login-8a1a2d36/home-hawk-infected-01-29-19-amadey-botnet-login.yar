rule _home_hawk_infected_01_29_19_amadey_botnet_login {
  meta:
    description = "amadey-botnet - file login.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "25007daf60f075efd0c6ac57559e1045dcc72a2b1ac8fa5de5bcf47b8a63ef72"

  strings:
    $s1  = "<form action=\\\"login.php\\\" method=\\\"post\\\"> " fullword ascii
    $s2  = "if ( isset( $_POST[\"login\"]) && isset( $_POST[\"password\"] ) )" fullword ascii
    $s3  = "if ( ( $login == $conf[\"observer_login\"] ) && ( md5( $password ) == $conf[\"observer_password\"] ) )" fullword ascii
    $s4  = "if ( ( $login == $conf[\"login\"] ) && ( md5( $password ) == $conf[\"password\"] ) )" fullword ascii
    $s5  = "$login = $_POST[\"login\"];" fullword ascii
    $s6  = "header( \"Location: login.php\" );" fullword ascii
    $s7  = "<meta http-equiv=\\\"Content-Type\\\" content=\\\"text/html; charset=windows-1251\\\">" fullword ascii
    $s8  = "$password = $_POST[\"password\"];" fullword ascii
    $s9  = "@header( \"Refresh: 0; url = statistic.php\" );" fullword ascii
    $s10 = "if ( $_GET['logout'] == 1 ) " fullword ascii
    $s11 = "<table width=\\\"515\\\" height=\\\"481\\\" background=\\\"images\\bg_1.png\\\">" fullword ascii
    $s12 = "<link rel=\\\"stylesheet\\\" type=\\\"text/css\\\" href=\\\"f.st\\style.css\\\">" fullword ascii
    $s13 = "<input type=\\\"text\\\" class=task name=\\\"login\\\">" fullword ascii
    $s14 = "<input type=\\\"password\\\" class=task name=\\\"password\\\">" fullword ascii
    $s15 = "<font size = 1 color = #8d8c8c>default root: root/root</font>" fullword ascii
    $s16 = "<table border=\\\"0\\\" height=\\\"120\\\" cellpadding=\\\"0\\\" cellspacing=\\\"0\\\">" fullword ascii
    $s17 = "include( \"cfg/config.php\" );" fullword ascii
    $s18 = "$_SESSION[\"Name\"] = \"ROOT\";" fullword ascii
    $s19 = "<font size = 1 color = #8d8c8c>default obs: observer/observer</font>" fullword ascii
    $s20 = "<font size = 2>a2019 \\\"AMADEY\\\"</font>&nbsp;&nbsp;&nbsp;&nbsp;" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (8 of them)
    ) or (all of them)
}