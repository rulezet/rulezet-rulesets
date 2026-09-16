rule infected_09_01_18_botnet_kit_botlogger {
  meta:
    description = "botnet-kit - file botlogger.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-01"
    hash1       = "2aceed18868bb5e8660869606517a7bc703906435cc47bba13445bd0ee2b7961"

  strings:
    $s1  = "$sessionTime = 5; //this is the time in **minutes** to consider someone online before removing them from our file" fullword ascii
    $s2  = "$users[] = rtrim(fgets($fp, 32));" fullword ascii
    $s3  = "if(time() - $lastvisit >= $sessionTime * 60) {" fullword ascii
    $s4  = "foreach($users as $key => $data) {" fullword ascii
    $s5  = "echo '<div style=\"padding:5px; margin:auto; background-color:#fff\"><b>' . $i . ' visitors online</b></div>';" fullword ascii
    $s6  = "$users[$x] = \"$ip|\" . time(); //updating" fullword ascii
    $s7  = "$users[] = \"$ip|\" . time();" fullword ascii
    $s8  = "foreach($users as $single) {" fullword ascii
    $s9  = "$onusers = array();" fullword ascii
    $s10 = "$users[$x] = \"\";" fullword ascii
    $s11 = "error_reporting(E_ERROR | E_PARSE);" fullword ascii
    $s12 = "$dataFile = \"visitors.txt\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 4KB and
      (8 of them)
    ) or (all of them)
}