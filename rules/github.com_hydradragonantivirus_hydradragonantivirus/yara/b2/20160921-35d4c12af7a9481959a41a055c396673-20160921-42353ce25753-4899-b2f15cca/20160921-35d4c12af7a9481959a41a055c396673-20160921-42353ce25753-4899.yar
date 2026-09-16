rule _20160921_35d4c12af7a9481959a41a055c396673_20160921_42353ce25753_4899 {
  meta:
    description = "datamaliciousorder - from files 20160921_35d4c12af7a9481959a41a055c396673.js, 20160921_42353ce257534ed06a8c73cebdde12dc.js, 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js, 20160921_c4afaa1e41efa7633248f1941bda4010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2412951fad30bb8b34aca279acd07c03a437936261b0d90334331b98cf1e99"
    hash2       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"
    hash3       = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"
    hash4       = "64cdab0c251929ea414823662957bad76268a8398b0c708715609f37e7070a69"

  strings:
    $s1 = "nction fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){retur" ascii
    $s2 = " \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"ZLd\";})(),(fun" ascii
    $s3 = "urn \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(fu" ascii
    $s4 = "ck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";" ascii
    $s5 = ";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}