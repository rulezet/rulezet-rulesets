rule _20160921_920f820521e7af7d81b11e9545080390_20160921_9ef73b9f4f78_1613 {
  meta:
    description = "datamaliciousorder - from files 20160921_920f820521e7af7d81b11e9545080390.js, 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4a6a94fe43f214f35574405d899a6d61259c2b1135c1ecf399630de11c6dea3"
    hash2       = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"

  strings:
    $s1  = "(function fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){re" ascii
    $s2  = "uck(){return \"XHj\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s3  = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"DWe\";})()" ascii
    $s4  = " \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s5  = "\"GNm\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(fun" ascii
    $s6  = "eturn \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s7  = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){" ascii
    $s8  = "n \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s9  = "(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck()" ascii
    $s10 = "})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})(),(function fu" ascii
    $s11 = "fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IR" ascii
    $s12 = "k(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}