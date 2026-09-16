rule TTP_XOR_QUAD_CurrentVersionRun_aed5 {
  strings:
    $key_aed5 = { fd ba [2] d9 b4 [2] f2 98 [2] dc ba [2] c8 a1 [2] c7 bb [2] d9 a6 [2] db a7 [2] c0 a1 [2] dc a6 [2] c0 89 }

  condition:
    any of them
}