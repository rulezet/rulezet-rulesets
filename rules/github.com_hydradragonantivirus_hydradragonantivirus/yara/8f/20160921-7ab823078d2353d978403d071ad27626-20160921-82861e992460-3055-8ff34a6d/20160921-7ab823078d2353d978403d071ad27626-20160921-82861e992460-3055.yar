rule _20160921_7ab823078d2353d978403d071ad27626_20160921_82861e992460_3055 {
  meta:
    description = "datamaliciousorder - from files 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_82861e992460412d02ca3f987da7d467.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash2       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"
    hash3       = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = "\"Yk\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s2 = "){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";" ascii
    $s3 = "n fuck(){return \"ZLd\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s4 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){" ascii
    $s5 = "ck(){return \"Xw\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"LLv\"" ascii
    $s6 = "eturn \"MIl\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s7 = "ion fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}