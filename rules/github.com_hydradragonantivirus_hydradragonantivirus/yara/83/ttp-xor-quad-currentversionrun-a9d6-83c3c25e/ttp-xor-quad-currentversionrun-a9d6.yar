rule TTP_XOR_QUAD_CurrentVersionRun_a9d6 {
  strings:
    $key_a9d6 = { fa b9 [2] de b7 [2] f5 9b [2] db b9 [2] cf a2 [2] c0 b8 [2] de a5 [2] dc a4 [2] c7 a2 [2] db a5 [2] c7 8a }

  condition:
    any of them
}