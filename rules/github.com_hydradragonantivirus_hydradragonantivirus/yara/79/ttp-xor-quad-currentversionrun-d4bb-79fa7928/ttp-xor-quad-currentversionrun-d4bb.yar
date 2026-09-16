rule TTP_XOR_QUAD_CurrentVersionRun_d4bb {
  strings:
    $key_d4bb = { 87 d4 [2] a3 da [2] 88 f6 [2] a6 d4 [2] b2 cf [2] bd d5 [2] a3 c8 [2] a1 c9 [2] ba cf [2] a6 c8 [2] ba e7 }

  condition:
    any of them
}