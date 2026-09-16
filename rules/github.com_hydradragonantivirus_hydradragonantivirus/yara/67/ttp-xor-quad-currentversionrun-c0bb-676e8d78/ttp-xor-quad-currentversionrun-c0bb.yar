rule TTP_XOR_QUAD_CurrentVersionRun_c0bb {
  strings:
    $key_c0bb = { 93 d4 [2] b7 da [2] 9c f6 [2] b2 d4 [2] a6 cf [2] a9 d5 [2] b7 c8 [2] b5 c9 [2] ae cf [2] b2 c8 [2] ae e7 }

  condition:
    any of them
}