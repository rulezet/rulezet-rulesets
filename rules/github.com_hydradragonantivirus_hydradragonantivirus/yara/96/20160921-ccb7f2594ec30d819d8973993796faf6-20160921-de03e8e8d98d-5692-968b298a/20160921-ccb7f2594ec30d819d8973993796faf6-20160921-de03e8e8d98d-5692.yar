rule _20160921_ccb7f2594ec30d819d8973993796faf6_20160921_de03e8e8d98d_5692 {
  meta:
    description = "datamaliciousorder - from files 20160921_ccb7f2594ec30d819d8973993796faf6.js, 20160921_de03e8e8d98da4b7d17147c979ce9ff8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"
    hash2       = "aa4eb617dd497a7ea1d016d98ce4ca8e81e13b4e240c42d46d01e84e617a150b"

  strings:
    $s1 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){re" ascii
    $s2 = "eturn \"QTc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(" ascii
    $s3 = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return" ascii
    $s4 = ";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function f" ascii
    $s5 = " fuck(){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}