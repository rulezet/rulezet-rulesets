rule _20160921_91734b00fd54cd3dd10c5f20c35d7864_20160921_d29f34806a7d_5540 {
  meta:
    description = "datamaliciousorder - from files 20160921_91734b00fd54cd3dd10c5f20c35d7864.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"
    hash2       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"

  strings:
    $s1 = "n \"OQr\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(fu" ascii
    $s2 = "\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function f" ascii
    $s3 = "n\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(functio" ascii
    $s4 = "(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XCr\";" ascii
    $s5 = "eturn \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Zy\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}