rule _20160921_6f8e01604e95009c9405a4a9c31cc901_20160921_a05dfc337c4a_5383 {
  meta:
    description = "datamaliciousorder - from files 20160921_6f8e01604e95009c9405a4a9c31cc901.js, 20160921_a05dfc337c4ada28e05759b304eef904.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"
    hash2       = "db6a3cf7e8281867bf38b22cce5a945336377679a1a85ee91d365e41ec94182c"

  strings:
    $s1 = "turn \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})()" ascii
    $s2 = "on fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s3 = "Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"RAi\";})(),(functi" ascii
    $s4 = "s\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function" ascii
    $s5 = "urn \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}