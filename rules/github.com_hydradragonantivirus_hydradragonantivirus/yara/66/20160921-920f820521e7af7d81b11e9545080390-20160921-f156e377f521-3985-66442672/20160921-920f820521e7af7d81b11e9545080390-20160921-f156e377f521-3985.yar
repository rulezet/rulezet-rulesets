rule _20160921_920f820521e7af7d81b11e9545080390_20160921_f156e377f521_3985 {
  meta:
    description = "datamaliciousorder - from files 20160921_920f820521e7af7d81b11e9545080390.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4a6a94fe43f214f35574405d899a6d61259c2b1135c1ecf399630de11c6dea3"
    hash2       = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"

  strings:
    $s1 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){ret" ascii
    $s2 = "n \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s3 = "uck(){return \"Wo\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs" ascii
    $s4 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return " ascii
    $s5 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"QTc\"" ascii
    $s6 = "(){return \"DAa\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}