rule wp_class_datlib {
  meta:
    description = "Navy - file wp_class_datlib.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2020-07-23"
    hash1       = "0ae7aa610ff4eace91d6a6d3130ad6133512f2d13554f25cfd0dec11c0c44cc0"

  strings:
    $s1  = "function T_($Bc) { $x2 = 256; $W2 = 8; $cY = array(); $I3 = 0; $C4 = 0; for ($bs = 0; $bs < strlen($Bc); $bs++) { $I3 = ($I3 << " ascii
    $s2  = "3JHLvKSvgGPIPE9yAGXLKa3J/GJSfL3H5SfMNknHXLh/3MtnvKtyAGfNnLfN4GfOKymz3MXLnQPP" fullword ascii
    $s3  = "$PASS=\"188162e90b88271030885b3bd7cfd523\";" fullword ascii
    $s4  = "HXXaC8fYfTPYzk6ZRWvW3Zjj/UXRfMfQ/aIEHaYhHXXcna/S/bJQSXaRiZfT3W/cHPYgLi/P3Ujb" fullword ascii
    $s5  = "8) + ord($Bc[$bs]); $C4 += 8; if ($C4 >= $W2) { $C4 -= $W2; $cY[] = $I3 >> $C4; $I3 &= (1 << $C4) - 1; $x2++; if ($x2 >> $W2) { " ascii
    $s6  = "4z8hbhSyUt2e4D8QKEz4I1RC/o2BCTlGms+0V6HI3m+TcEgEu+ltq8aANI2x16ijoGGeT2wOAV6J" fullword ascii
    $s7  = "Azgc4tP/IHCelOP0CDxTP1uayJJQLDotAlP4HF7Ha5i0DdAFP3k5k5gLuTo05zPezuU/xQTTk05w" fullword ascii
    $s8  = "QnE9sr0fZFYQsLOG45h+RWREbgHx4TEelsyelFlR+KjKujjtwYqsRRWRLPDGwVUWItQxYw7dFkRI" fullword ascii
    $s9  = "NqCiZF5aDChQpgISAwhpeRqMwZG4C6DADu0KDClwIoDFkiqrqaBkVWp0cUDTgFWNDkp4chvscINf" fullword ascii
    $s10 = "8DNKkkKJxiAxgsp34XcMpzzzQdooD5KlnMDj6I+Wh/JH2AxnvAK2EDljwBICMHWEk6DQspyDW+YP" fullword ascii
    $s11 = "So2jvQ3oAKFiKAbgPeBfwD6kE438GGWl0q7I08YU2l+3qY224MYyNFuG3HE+ItiAREYe4MXGTGTB" fullword ascii
    $s12 = "ROE9ylT+gBf2R5TdjOsPY7imMEh09khkvZROB2W6edUgwwUYBcHwElx/iM2I6qZyJ3Gkfo+BPMXF" fullword ascii
    $s13 = "QM46xtrz66sVLGQMivL0QGAEsJQPEB628ibqMioHaDkCMECqUV75KxBBI4UN0hjuqCoMorRcsh0J" fullword ascii
    $s14 = "NTbV21hEkBeFk9JDKxsWodhLpL8qnvLXTFMuHR0NZmscmD+FJhXrHuFZhXVows0RXatK3St1KSJQ" fullword ascii
    $s15 = "7FunwaP7COmvsWi2ofDn5L/SwwKR6nIpznp6M+qYZaHeOefrHAJIOHrP4vIODaQGBj2x/SM1jqQh" fullword ascii
    $s16 = "IMRqbpkUonrCnjU3T4DJJ/sGZaaOcomzMXD41dEeSPKnpfXO6ogY1YgdV8rx11j9OjM5SrpmRIKk" fullword ascii
    $s17 = "Y5oHUY8X7M8aLeYGMNkDa9y2S2kYa263LrAGQGoGQM0FypMK0L8JTrpwrr63rxQMzD8RhBIN8aMZ" fullword ascii
    $s18 = "gNykKVYHtBjHYMoFIH86EO9gFd1bINlbdjRJiooL4KIKoJ4KgIoh1ethtfFaBSdiQE9iliwOVjFg" fullword ascii
    $s19 = "g0X6zLC5c+wPTZsFa8deeSjXrVH1ta3Jb+t6xGrLCwZysOxK8Cmd+ncTsi5OdEIDkEEDwlSi5ckp" fullword ascii
    $s20 = "aZBrCS+UyKUitay2JyQVCoUC+VbUUi+QSORScVBOXRTO4AIIFBINCBIXyGTyeSySRS3ZbPibvbSl" fullword ascii

  condition:
    uint16(0) == 0x3f3c and filesize < 100KB and
    8 of them
}