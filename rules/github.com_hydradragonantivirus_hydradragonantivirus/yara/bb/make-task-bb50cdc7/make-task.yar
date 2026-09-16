rule make_task {
  meta:
    description = "amadey-botnet - file make_task.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "87d952f000b19475ca7f9e815653746bc17c48cb69fbce19b8036fb4e731c770"

  strings:
    $x1  = "* Chosen country, * for any. <a href=\\\"images/task_example.png\\\" target=\\\"_blank\\\">Example<" fullword ascii
    $s2  = "MakeTask( $_POST['path']  . \":::\" . $_POST['dllfunction'], \"0\", $_POST['filetype'], $_POST['autorun'], $_POST['count']" fullword ascii
    $s3  = "/a>. <a href=\\\"f.st\\c.index.txt\\\" target=\\\"_blank\\\">Countries <b>index</b> table</a>." fullword ascii
    $s4  = "* Chosen country, * for any. <a href=\\\"images/task_example.png\\\" target=\\\"_blank\\\">Example</a>. <a href=\\\"f.st\\c.inde" ascii
    $s5  = "<input name=\\\"path\\\" class=task value=\\\"http://site.com/folder/exe.e\\\" style=\\\"float: left\\\" size=\\\"50\\\">" fullword ascii
    $s6  = "MakeTask( $_POST['path'], $_POST['run'], $_POST['filetype'], $_POST['autorun'], $_POST['count'], $_POST['unitid'], $_P" fullword ascii
    $s7  = "echo \"<meta http-equiv=\\\"refresh\\\" content=\\\"1; url=show_tasks.php\\\">\"; " fullword ascii
    $s8  = "* Startup options, <b>only for EXE</b>. Warning! Do not change this option if you don't know what it is." fullword ascii
    $s9  = "<form action=\\\"\" . basename( $_SERVER['SCRIPT_NAME'] ) . \"\\\" method=\\\"post\\\" name=\\\"form\\\">" fullword ascii
    $s10 = "header( \"Location: login.php\" );" fullword ascii
    $s11 = "* Startup options, <b>only for EXE</b>. Warning! Do not change this option if you don't kno" fullword ascii
    $s12 = "mysql_query( \"INSERT INTO tasks ( `path`, `run`, `filetype`, `autorun`, `tlimit`, `units`, `country` ) VALUES ( '$url', '$run" fullword ascii
    $s13 = "mysql_query( \"INSERT INTO tasks ( `id`, `path`, `run`, `filetype`, `autorun`, `tlimit`, `units`, `country` ) VALUES (  '10000" fullword ascii
    $s14 = "* Web URL, file will be saved with original name, expansion will be changed." fullword ascii
    $s15 = "mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ); " fullword ascii
    $s16 = "* Name of the calling function, <b>only for DLL</b>." fullword ascii
    $s17 = "echo \"Please login at root, observers cant make task\"; " fullword ascii
    $s18 = "01', '$url', '$run', '$filetype', '$autorun', '$limit', '$units', '$country' )\" ); " fullword ascii
    $s19 = "MakeTask( $_POST['path']  . \":::\" . $_POST['dllfunction'], \"0\", $_POST['filetype'], $_POST['autorun'], $_POST['count'], $_PO" ascii
    $s20 = "<table border=\\\"0\\\" width=\\\"1000\\\" cellspacing=\\\"0\\\" cellpadding=\\\"0\\\" height=\\\"5\\\">" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 30KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}