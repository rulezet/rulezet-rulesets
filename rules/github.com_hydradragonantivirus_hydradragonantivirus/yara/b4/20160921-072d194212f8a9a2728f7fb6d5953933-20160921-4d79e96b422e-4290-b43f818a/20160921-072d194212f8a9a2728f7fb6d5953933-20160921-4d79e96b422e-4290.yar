rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_4d79e96b422e_4290 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_4d79e96b422e6679059a17d9524e032c.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "d5794a16a28dba8e89768fa9195da33a7e28c3da5fc73a7789e7c04395f23f06"
    hash3       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"

  strings:
    $s1 = "urn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"FJs\";})(),(f" ascii
    $s2 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){r" ascii
    $s3 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return" ascii
    $s4 = "(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(" ascii
    $s5 = "turn \"QTc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}