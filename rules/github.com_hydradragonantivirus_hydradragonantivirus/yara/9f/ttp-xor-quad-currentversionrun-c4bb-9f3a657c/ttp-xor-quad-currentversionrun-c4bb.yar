rule TTP_XOR_QUAD_CurrentVersionRun_c4bb {
  strings:
    $key_c4bb = { 97 d4 [2] b3 da [2] 98 f6 [2] b6 d4 [2] a2 cf [2] ad d5 [2] b3 c8 [2] b1 c9 [2] aa cf [2] b6 c8 [2] aa e7 }

  condition:
    any of them
}