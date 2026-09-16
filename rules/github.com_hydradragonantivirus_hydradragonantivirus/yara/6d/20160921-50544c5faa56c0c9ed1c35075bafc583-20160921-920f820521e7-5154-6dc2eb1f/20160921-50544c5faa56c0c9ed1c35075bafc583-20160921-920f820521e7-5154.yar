rule _20160921_50544c5faa56c0c9ed1c35075bafc583_20160921_920f820521e7_5154 {
  meta:
    description = "datamaliciousorder - from files 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_920f820521e7af7d81b11e9545080390.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash2       = "c4a6a94fe43f214f35574405d899a6d61259c2b1135c1ecf399630de11c6dea3"

  strings:
    $s1 = " fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"AU" ascii
    $s2 = "ck(){return \"Ot\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";" ascii
    $s3 = "(function fuck(){return \"UOe\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){" ascii
    $s4 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"UXf\";})(),(function " ascii
    $s5 = "),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}