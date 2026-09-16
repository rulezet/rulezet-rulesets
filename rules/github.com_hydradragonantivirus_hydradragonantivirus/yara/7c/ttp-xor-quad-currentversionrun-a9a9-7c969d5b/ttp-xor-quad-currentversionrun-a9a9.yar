rule TTP_XOR_QUAD_CurrentVersionRun_a9a9 {
  strings:
    $key_a9a9 = { fa c6 [2] de c8 [2] f5 e4 [2] db c6 [2] cf dd [2] c0 c7 [2] de da [2] dc db [2] c7 dd [2] db da [2] c7 f5 }

  condition:
    any of them
}