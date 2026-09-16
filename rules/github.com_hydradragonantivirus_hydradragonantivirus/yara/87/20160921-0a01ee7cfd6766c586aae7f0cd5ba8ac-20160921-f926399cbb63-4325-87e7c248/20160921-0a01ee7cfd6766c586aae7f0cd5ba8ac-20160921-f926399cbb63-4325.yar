rule _20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac_20160921_f926399cbb63_4325 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab92df4d278f844bff1f6b011a9c332faae5828bb4324384139b2829693be23b"
    hash2       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){re" ascii
    $s2 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s3 = "fuck(){return \"Qh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s4 = "(){return \"Ai\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IRn\";}" ascii
    $s5 = "urn \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}