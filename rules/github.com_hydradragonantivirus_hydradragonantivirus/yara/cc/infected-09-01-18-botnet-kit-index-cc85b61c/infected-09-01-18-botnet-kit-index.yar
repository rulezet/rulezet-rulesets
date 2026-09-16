rule infected_09_01_18_botnet_kit_index {
  meta:
    description = "botnet-kit - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-01"
    hash1       = "3653e310cd3937134ad1b7dcfe3e9b2e6fba37800d0dd9bbfec189ae4a3e38c3"

  strings:
    $s1  = "<script src=\"http://code.jquery.com/jquery.js\"></script>" fullword ascii
    $s2  = "$sessionTime = 5; //this is the time in **minutes** to consider someone online before removing them from our file" fullword ascii
    $s3  = "header(\"Location: login.php\");" fullword ascii
    $s4  = "$users[] = rtrim(fgets($fp, 32));" fullword ascii
    $s5  = "$fh = fopen(\"target.port\", 'w+');" fullword ascii
    $s6  = "if(time() - $lastvisit >= $sessionTime * 60) {" fullword ascii
    $s7  = "<title>LOLZTEAM.COM | Blue Botnet CPANEL</title>" fullword ascii
    $s8  = "$filename = \"target.port\";" fullword ascii
    $s9  = "foreach($users as $key => $data) {" fullword ascii
    $s10 = "<!-- jQuery e plugin JavaScript  -->" fullword ascii
    $s11 = "$fh = fopen(\"target.method\", 'w+');" fullword ascii
    $s12 = "$fh = fopen(\"target.ip\", 'w+');" fullword ascii
    $s13 = "$content = fread($fp, filesize($filename));" fullword ascii
    $s14 = "<form action=\"index.php\" method=\"post\">" fullword ascii
    $s15 = "$users[$x] = \"$ip|\" . time(); //updating" fullword ascii
    $s16 = "$fh = fopen(\"target\", 'w+');" fullword ascii
    $s17 = "$filename = \"target.method\";" fullword ascii
    $s18 = "<li><a href=\"logout.php\">Logout</a></li>" fullword ascii
    $s19 = "$filename = \"target.ip\";" fullword ascii
    $s20 = "<link href=\"css/stili-custom.css\" rel=\"stylesheet\" media=\"screen\">" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (8 of them)
    ) or (all of them)
}