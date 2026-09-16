rule _20160921_9b04118eed50c5e7331c4157a5c4dfc8_20160921_d905978b34be_5585 {
  meta:
    description = "datamaliciousorder - from files 20160921_9b04118eed50c5e7331c4157a5c4dfc8.js, 20160921_d905978b34bea5948e843dd7ecb9dc6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdb29344d617d9ae88ae6d7109bec25567e1c486cbb28c248a65e9f2a678c75d"
    hash2       = "8110e9072a75f1960f23243cc11d3c233a350d63360d8006cad608a2fb81e0b3"

  strings:
    $s1 = " fuck(){return \"XHj\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"O" ascii
    $s2 = ";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ve\";})(),(function fuck" ascii
    $s3 = "(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Qh\";})" ascii
    $s4 = "{return \"ADy\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})" ascii
    $s5 = "b\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}