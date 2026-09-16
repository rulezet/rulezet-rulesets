rule _20160921_06a7c56eaf19048ede06f33b655f2bc5_20160921_11906f10ee01_3261 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a7c56eaf19048ede06f33b655f2bc5.js, 20160921_11906f10ee01a55012f649f6f86dd24b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3971833c2ab49de293c47181e999db88e5cad0eaddc5aa38a2516eeac1cab29d"
    hash2       = "f7e3d843ddea21ba91cad5bd21d3e536f69426d4c4c5a060bbfe7f1f967bda27"

  strings:
    $s1 = "eturn \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s2 = "{return \"ILp\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"ILp\";})(" ascii
    $s3 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(fu" ascii
    $s4 = "on fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s5 = "})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fu" ascii
    $s6 = "ion fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}