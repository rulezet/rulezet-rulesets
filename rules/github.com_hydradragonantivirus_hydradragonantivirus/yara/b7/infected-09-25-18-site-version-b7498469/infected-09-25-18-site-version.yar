rule infected_09_25_18_site_version {
  meta:
    description = "shell2 - file site-version.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-25"
    hash1       = "b131f3261fd40891decdcc5df429b2abb50cb12827a94cbaf994e29974affd38"

  strings:
    $s1 = "* Show Site Version Administration Settings" fullword ascii
    $s2 = "/** Show Enrcypted WordPress Version */" fullword ascii
    $s3 = "$p28 = \"\\x70\\x72\\x65\\x67\\x5F\\x72\\x65\\x70\\x6C\\x61\\x63\\x65\";" fullword ascii
    $s4 = "if ($_REQUEST['wp_version_info']) {" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}