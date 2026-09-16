rule _20160921_ce3c0604d52e9dc9119cefedfee34385_20160921_e0f7b2a32a09_5695 {
  meta:
    description = "datamaliciousorder - from files 20160921_ce3c0604d52e9dc9119cefedfee34385.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"
    hash2       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1 = " fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"" ascii
    $s2 = "urn \"Wo0\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s3 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"SU" ascii
    $s4 = ")(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck" ascii
    $s5 = ",(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}