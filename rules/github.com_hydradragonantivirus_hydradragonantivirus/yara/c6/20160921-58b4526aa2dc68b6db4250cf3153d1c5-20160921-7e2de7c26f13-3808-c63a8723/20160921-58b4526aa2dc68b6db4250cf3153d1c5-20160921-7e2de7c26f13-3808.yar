rule _20160921_58b4526aa2dc68b6db4250cf3153d1c5_20160921_7e2de7c26f13_3808 {
  meta:
    description = "datamaliciousorder - from files 20160921_58b4526aa2dc68b6db4250cf3153d1c5.js, 20160921_7e2de7c26f136a1a958818752613cac3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8879fc10234de7d36f536a9cdb49bc5cf37dfb897d610b0eeba644033852dd92"
    hash2       = "540bec3c8538992ab2a631157eae2d03acb2afd24ba0842fcdbbcd7a792913b3"

  strings:
    $s1 = "nction fuck(){return \"Cd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){retur" ascii
    $s2 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){retu" ascii
    $s3 = "g\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s4 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){" ascii
    $s5 = "nction fuck(){return \"TTs\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){ret" ascii
    $s6 = "uck(){return \"Yk\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MOj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}