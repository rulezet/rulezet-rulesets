rule TTP_XOR_QUAD_CurrentVersionRun_a9b9 {
  strings:
    $key_a9b9 = { fa d6 [2] de d8 [2] f5 f4 [2] db d6 [2] cf cd [2] c0 d7 [2] de ca [2] dc cb [2] c7 cd [2] db ca [2] c7 e5 }

  condition:
    any of them
}