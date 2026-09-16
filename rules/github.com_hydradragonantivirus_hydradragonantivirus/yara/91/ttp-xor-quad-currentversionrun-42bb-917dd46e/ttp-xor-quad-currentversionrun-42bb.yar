rule TTP_XOR_QUAD_CurrentVersionRun_42bb {
  strings:
    $key_42bb = { 11 d4 [2] 35 da [2] 1e f6 [2] 30 d4 [2] 24 cf [2] 2b d5 [2] 35 c8 [2] 37 c9 [2] 2c cf [2] 30 c8 [2] 2c e7 }

  condition:
    any of them
}