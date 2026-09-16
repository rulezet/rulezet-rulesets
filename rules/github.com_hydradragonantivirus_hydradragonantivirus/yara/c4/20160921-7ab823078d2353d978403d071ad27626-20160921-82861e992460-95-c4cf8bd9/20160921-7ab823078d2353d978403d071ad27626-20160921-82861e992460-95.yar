rule _20160921_7ab823078d2353d978403d071ad27626_20160921_82861e992460_95 {
  meta:
    description = "datamaliciousorder - from files 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_82861e992460412d02ca3f987da7d467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash2       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"

  strings:
    $s1  = "return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})" ascii
    $s2  = "uck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np" ascii
    $s3  = "n \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(func" ascii
    $s4  = "turn \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(f" ascii
    $s5  = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s6  = "turn \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ai\";})(),(" ascii
    $s7  = "){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";" ascii
    $s8  = "\"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"To\";})(),(funct" ascii
    $s9  = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s10 = "ck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\"" ascii
    $s11 = "rn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"FJs\";})(),(f" ascii
    $s12 = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Mw\";})(),(fun" ascii
    $s13 = " fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"W" ascii
    $s14 = "Wu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s15 = "eturn \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s16 = "unction fuck(){return \"IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){ret" ascii
    $s17 = "Df\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s18 = "n \"UOe\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(fu" ascii
    $s19 = "\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function f" ascii
    $s20 = "uck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}