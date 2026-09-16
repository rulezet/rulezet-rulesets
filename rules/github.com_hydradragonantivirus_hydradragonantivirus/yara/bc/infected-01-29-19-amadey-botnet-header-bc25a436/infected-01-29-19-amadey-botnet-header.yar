rule infected_01_29_19_amadey_botnet_header {
  meta:
    description = "amadey-botnet - file header.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "44227b5c4367fdedd1ae532fd00c57b9543b5261a68946a51f6ec11294bbb4fd"

  strings:
    $s1  = "<img src=\\\"images\\b6.png\\\"> <a href=\\\"login.php?logout=1\\\"><font color=\\\"#DDDDDD\\\">LOGOUT [\";" fullword ascii
    $s2  = "<td bgcolor=\\\"#FF0000\\\"><div align=\\\"center\\\"><img src=\\\"images\\logo_small.png\\\"></div></td>" fullword ascii
    $s3  = "<img src=\\\"images\\b1.png\\\"> <a href=\\\"statistic.php\\\"><font color=\\\"#DDDDDD\\\">STATISTIC</font></a>&nbsp; |&nbsp;" fullword ascii
    $s4  = "<img src=\\\"images\\b5.png\\\"> <a href=\\\"settings.php\\\"><font color=\\\"#DDDDDD\\\">SETTINGS</font></a>&nbsp; |&nbsp;" fullword ascii
    $s5  = "<img src=\\\"images\\b4.png\\\"> <a href=\\\"show_tasks.php\\\"><font color=\\\"#DDDDDD\\\">TASKS LIST</font></a>&nbsp; |&nbsp;" fullword ascii
    $s6  = "<meta http-equiv=\\\"Content-Type\\\" content=\\\"text/html; charset=windows-1251\\\">" fullword ascii
    $s7  = "<img src=\\\"images\\b5.png\\\"> <a href=\\\"settings.php\\\"><font color=\\\"#DDDDDD\\\">SETTINGS</font></a>" fullword ascii
    $s8  = "echo \"<table border=\\\"0\\\" width=\\\"100%\\\" cellspacing=\\\"0\\\" cellpadding=\\\"0\\\" bgcolor=\\\"#000000\\\">" fullword ascii
    $s9  = "echo \"<table border=\\\"0\\\" width=\\\"1000\\\" cellspacing=\\\"0\\\" cellpadding=\\\"0\\\" height=\\\"5\\\">" fullword ascii
    $s10 = "<link rel=\\\"stylesheet\\\" type=\\\"text/css\\\" href=\\\"f.st\\style.css\\\">" fullword ascii
    $s11 = "<table border=\\\"0\\\" width=\\\"1200\\\" cellspacing=\\\"0\\\" cellpadding=\\\"0\\\" height=\\\"100%\\\">" fullword ascii
    $s12 = "<td align=\\\"center\\\"><font color=\\\"#DDDDDD\\\" size=\\\"4\\\">" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 5KB and
      (8 of them)
    ) or (all of them)
}