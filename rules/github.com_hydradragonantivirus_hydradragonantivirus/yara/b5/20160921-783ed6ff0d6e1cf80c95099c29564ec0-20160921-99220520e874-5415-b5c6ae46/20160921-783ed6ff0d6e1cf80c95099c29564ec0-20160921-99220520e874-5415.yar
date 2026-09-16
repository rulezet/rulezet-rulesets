rule _20160921_783ed6ff0d6e1cf80c95099c29564ec0_20160921_99220520e874_5415 {
  meta:
    description = "datamaliciousorder - from files 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_99220520e87414c0f2e1267cf4078a22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash2       = "5b655a405ebc3a6ee1687faec5788f37e732bcfe1afd9f30936ca55a4983a755"

  strings:
    $s1 = "k(){return \"GJx\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\"" ascii
    $s2 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){ret" ascii
    $s3 = "){return \"Nm\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s4 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return " ascii
    $s5 = "})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Jo\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}