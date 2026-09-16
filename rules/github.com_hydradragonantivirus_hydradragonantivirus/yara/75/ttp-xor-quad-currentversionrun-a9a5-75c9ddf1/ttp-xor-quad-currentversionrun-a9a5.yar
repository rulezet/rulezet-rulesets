rule TTP_XOR_QUAD_CurrentVersionRun_a9a5 {
  strings:
    $key_a9a5 = { fa ca [2] de c4 [2] f5 e8 [2] db ca [2] cf d1 [2] c0 cb [2] de d6 [2] dc d7 [2] c7 d1 [2] db d6 [2] c7 f9 }

  condition:
    any of them
}