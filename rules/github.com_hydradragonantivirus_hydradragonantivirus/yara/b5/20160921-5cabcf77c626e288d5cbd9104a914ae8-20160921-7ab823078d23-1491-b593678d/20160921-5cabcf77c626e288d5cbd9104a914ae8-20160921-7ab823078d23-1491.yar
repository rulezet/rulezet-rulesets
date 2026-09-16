rule _20160921_5cabcf77c626e288d5cbd9104a914ae8_20160921_7ab823078d23_1491 {
  meta:
    description = "datamaliciousorder - from files 20160921_5cabcf77c626e288d5cbd9104a914ae8.js, 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_82861e992460412d02ca3f987da7d467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9493e4251106014081e4b141c6296c51b00c9ba7a799bcb978ea6226cd127d34"
    hash2       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash3       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"

  strings:
    $s1  = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii
    $s2  = "(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"ADy\";})(),(function fuck" ascii
    $s3  = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return" ascii
    $s4  = "p\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function" ascii
    $s5  = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s6  = "k(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Za\";" ascii
    $s7  = "nction fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii
    $s8  = " fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv" ascii
    $s9  = " \"Et\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s10 = "n fuck(){return \"Oh\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IP" ascii
    $s11 = "urn \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s12 = "(){return \"CTm\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\"" ascii
    $s13 = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}