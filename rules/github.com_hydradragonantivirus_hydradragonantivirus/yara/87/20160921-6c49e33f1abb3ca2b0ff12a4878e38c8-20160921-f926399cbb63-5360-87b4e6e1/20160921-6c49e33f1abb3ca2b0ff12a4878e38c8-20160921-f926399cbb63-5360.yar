rule _20160921_6c49e33f1abb3ca2b0ff12a4878e38c8_20160921_f926399cbb63_5360 {
  meta:
    description = "datamaliciousorder - from files 20160921_6c49e33f1abb3ca2b0ff12a4878e38c8.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c5f6e5a1ebce2cb0eb54f0d28ea21ab88b07dc646376bb3fc5ce29af1615aa"
    hash2       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = "nction fuck(){return \"QTc\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s2 = "turn \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s3 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Wo\";" ascii
    $s4 = " fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"D" ascii
    $s5 = "k(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}