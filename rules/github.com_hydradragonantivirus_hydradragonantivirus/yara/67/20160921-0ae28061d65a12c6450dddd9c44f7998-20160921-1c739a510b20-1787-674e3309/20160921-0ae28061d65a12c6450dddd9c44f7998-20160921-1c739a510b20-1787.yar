rule _20160921_0ae28061d65a12c6450dddd9c44f7998_20160921_1c739a510b20_1787 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ae28061d65a12c6450dddd9c44f7998.js, 20160921_1c739a510b202fd8658c1445b926e28b.js, 20160921_5c9dd9a0e8a8b3e5e8713af8aeaa5d59.js, 20160921_dd42e850834f3af27a08edf609a699b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2262aefc89b27a9a5b4507f43a6978eafd72ba25a305a11cdeb589d958f0e0a6"
    hash2       = "ef5e44b6b8f05f9e4eadc507955ef770936acdd360f7dcfe6bb70a36427b04b7"
    hash3       = "415a66b711143ada4e334e2da2ea19ca0e94ec191118672a58fa21828a1cd877"
    hash4       = "d7708087ab30a8d0d937f9d460512c05c37534c0d3c387bd3e1dd7fcb84fdc58"

  strings:
    $s1  = "ction fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){retur" ascii
    $s2  = "function fuck(){return \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){re" ascii
    $s3  = "),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){" ascii
    $s4  = ")(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MIl\";})(),(function fuc" ascii
    $s5  = "n \"YQt\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s6  = "n \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s7  = "ck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"EHo" ascii
    $s8  = "\"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"KVh\";})(),(func" ascii
    $s9  = " fuck(){return \"Sx\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"C" ascii
    $s10 = "turn \"Sx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ot\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}