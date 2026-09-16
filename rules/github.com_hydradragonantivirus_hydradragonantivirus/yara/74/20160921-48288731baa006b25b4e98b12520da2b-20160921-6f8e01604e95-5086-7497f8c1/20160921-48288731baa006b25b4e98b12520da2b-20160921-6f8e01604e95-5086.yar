rule _20160921_48288731baa006b25b4e98b12520da2b_20160921_6f8e01604e95_5086 {
  meta:
    description = "datamaliciousorder - from files 20160921_48288731baa006b25b4e98b12520da2b.js, 20160921_6f8e01604e95009c9405a4a9c31cc901.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce917015afcf31459cc47b8864f85394a756701f6338f6a2cbe079779c3ecd43"
    hash2       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"

  strings:
    $s1 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"" ascii
    $s2 = "turn \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LLv\";})()," ascii
    $s3 = ",(function fuck(){return \"Py\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s4 = "ck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\"" ascii
    $s5 = "ion fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}