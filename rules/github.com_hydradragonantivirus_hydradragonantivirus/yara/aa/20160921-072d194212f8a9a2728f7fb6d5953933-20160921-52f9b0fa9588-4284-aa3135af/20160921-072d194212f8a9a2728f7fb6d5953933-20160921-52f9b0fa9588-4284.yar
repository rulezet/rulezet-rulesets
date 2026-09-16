rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_52f9b0fa9588_4284 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_884f773b3c246c835029fc91499fb017.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash3       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"
    hash4       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"

  strings:
    $s1 = "(function fuck(){return \"MBg\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){r" ascii
    $s2 = "turn \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})()," ascii
    $s3 = "\"UXf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(func" ascii
    $s4 = "n fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s5 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}