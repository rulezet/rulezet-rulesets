rule _20160921_3823f4aff4d341a62056d936e59de44c_20160921_91734b00fd54_2881 {
  meta:
    description = "datamaliciousorder - from files 20160921_3823f4aff4d341a62056d936e59de44c.js, 20160921_91734b00fd54cd3dd10c5f20c35d7864.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b475c02138425371c1df69faa8ac5c3d739764950c4a65034372b4455ac04d"
    hash2       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"

  strings:
    $s1 = "n \"MUs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(fun" ascii
    $s2 = "ck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Oh\"" ascii
    $s3 = "urn \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s4 = "(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";" ascii
    $s5 = "),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck()" ascii
    $s6 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"W" ascii
    $s7 = "unction fuck(){return \"Vf\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}