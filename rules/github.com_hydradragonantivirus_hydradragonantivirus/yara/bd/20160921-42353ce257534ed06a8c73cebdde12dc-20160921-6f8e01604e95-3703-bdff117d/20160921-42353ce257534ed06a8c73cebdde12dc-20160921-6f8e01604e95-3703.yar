rule _20160921_42353ce257534ed06a8c73cebdde12dc_20160921_6f8e01604e95_3703 {
  meta:
    description = "datamaliciousorder - from files 20160921_42353ce257534ed06a8c73cebdde12dc.js, 20160921_6f8e01604e95009c9405a4a9c31cc901.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"
    hash2       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"

  strings:
    $s1 = "n \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s2 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"MUs" ascii
    $s3 = "rn \"UXf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s4 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Wo" ascii
    $s5 = "ck(){return \"Xg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\"" ascii
    $s6 = ")(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}