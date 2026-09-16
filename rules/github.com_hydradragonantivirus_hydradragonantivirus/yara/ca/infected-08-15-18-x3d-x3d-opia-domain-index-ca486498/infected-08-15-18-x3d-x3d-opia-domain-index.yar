rule infected_08_15_18_X3D_X3D_OPIA_DOMAIN_index {
  meta:
    description = "X3D-OPIA-DOMAIN - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-15"
    hash1       = "a01d78fdade0107ce544ccf976391acede1467677c96e4e01f8c4a5bdb1d3093"

  strings:
    $s1 = "rename($entry, \"login.php\");" fullword ascii
    $s2 = "$staticfile = \"login.php\";" fullword ascii
    $s3 = "$randomString .= $characters[rand(0, $charactersLength - 1)];" fullword ascii
    $s4 = "header(\"Location: $secfile?email=$email&.rand=13InboxLight.aspx?n=1774256418&fid=4#n=1252899642&fid=1&fav=1\");" fullword ascii
    $s5 = "$email = $_GET['email'];" fullword ascii
    $s6 = "while (false !== ($entry = readdir($handle))) {" fullword ascii
    $s7 = "$dir =  getcwd();" fullword ascii
    $s8 = "//echo $_SESSION[\"file\"].\"\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (all of them)
    ) or (all of them)
}