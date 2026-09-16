rule TTP_XOR_QUAD_CurrentVersionRun_a9aa {
  strings:
    $key_a9aa = { fa c5 [2] de cb [2] f5 e7 [2] db c5 [2] cf de [2] c0 c4 [2] de d9 [2] dc d8 [2] c7 de [2] db d9 [2] c7 f6 }

  condition:
    any of them
}