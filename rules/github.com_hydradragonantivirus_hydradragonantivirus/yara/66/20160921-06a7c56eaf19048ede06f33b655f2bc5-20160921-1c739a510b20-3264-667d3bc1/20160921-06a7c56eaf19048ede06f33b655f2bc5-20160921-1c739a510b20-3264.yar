rule _20160921_06a7c56eaf19048ede06f33b655f2bc5_20160921_1c739a510b20_3264 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a7c56eaf19048ede06f33b655f2bc5.js, 20160921_1c739a510b202fd8658c1445b926e28b.js, 20160921_dd42e850834f3af27a08edf609a699b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3971833c2ab49de293c47181e999db88e5cad0eaddc5aa38a2516eeac1cab29d"
    hash2       = "ef5e44b6b8f05f9e4eadc507955ef770936acdd360f7dcfe6bb70a36427b04b7"
    hash3       = "d7708087ab30a8d0d937f9d460512c05c37534c0d3c387bd3e1dd7fcb84fdc58"

  strings:
    $s1 = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"L" ascii
    $s2 = "rn \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s3 = "\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(function f" ascii
    $s4 = "{return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"KVh\";}" ascii
    $s5 = "ction fuck(){return \"Jg\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retur" ascii
    $s6 = "u\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}