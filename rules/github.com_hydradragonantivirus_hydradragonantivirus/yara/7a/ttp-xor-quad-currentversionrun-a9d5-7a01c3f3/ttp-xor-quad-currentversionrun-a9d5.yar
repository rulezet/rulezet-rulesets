rule TTP_XOR_QUAD_CurrentVersionRun_a9d5 {
  strings:
    $key_a9d5 = { fa ba [2] de b4 [2] f5 98 [2] db ba [2] cf a1 [2] c0 bb [2] de a6 [2] dc a7 [2] c7 a1 [2] db a6 [2] c7 89 }

  condition:
    any of them
}