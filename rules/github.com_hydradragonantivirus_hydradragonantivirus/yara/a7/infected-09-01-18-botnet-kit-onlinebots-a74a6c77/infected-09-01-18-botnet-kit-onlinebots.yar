rule infected_09_01_18_botnet_kit_onlinebots {
  meta:
    description = "botnet-kit - file onlinebots.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-01"
    hash1       = "6c741cfb37f2f963df3d3a529648e2430618fd46d0a940b8b68577c687b18d83"

  strings:
    $s1  = "<script src=\"http://code.jquery.com/jquery.js\"></script>" fullword ascii
    $s2  = "$sessionTime = 5; //this is the time in **minutes** to consider someone online before removing them from our file" fullword ascii
    $s3  = "header(\"Location: login.php\");" fullword ascii
    $s4  = "$users[] = rtrim(fgets($fp, 32));" fullword ascii
    $s5  = "$fh = fopen(\"target.port\", 'w+');" fullword ascii
    $s6  = "if(time() - $lastvisit >= $sessionTime * 60) {" fullword ascii
    $s7  = "foreach($users as $key => $data) {" fullword ascii
    $s8  = "<!-- jQuery e plugin JavaScript  -->" fullword ascii
    $s9  = "$fh = fopen(\"target.method\", 'w+');" fullword ascii
    $s10 = "$fh = fopen(\"target.ip\", 'w+');" fullword ascii
    $s11 = "$content = fread($fp, filesize($filename));" fullword ascii
    $s12 = "<form action=\"index.php\" method=\"post\">" fullword ascii
    $s13 = "$users[$x] = \"$ip|\" . time(); //updating" fullword ascii
    $s14 = "<li><a href=\"logout.php\">Logout</a></li>" fullword ascii
    $s15 = "for ($i=0; $i<count($bots) - 1; $i++){" fullword ascii
    $s16 = "<link href=\"css/stili-custom.css\" rel=\"stylesheet\" media=\"screen\">" fullword ascii
    $s17 = "$storedPassHash = $content;" fullword ascii
    $s18 = "$ip = $_POST['ipaddress'];" fullword ascii
    $s19 = "<!-- respond.js per IE8 -->" fullword ascii
    $s20 = "$ip = $_GET['ipaddress'];" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 10KB and
      (8 of them)
    ) or (all of them)
}