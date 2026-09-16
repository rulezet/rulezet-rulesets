rule TTP_XOR_QUAD_CurrentVersionRun_32bb {
  strings:
    $key_32bb = { 61 d4 [2] 45 da [2] 6e f6 [2] 40 d4 [2] 54 cf [2] 5b d5 [2] 45 c8 [2] 47 c9 [2] 5c cf [2] 40 c8 [2] 5c e7 }

  condition:
    any of them
}