rule TTP_XOR_QUAD_CurrentVersionRun_07bb {
  strings:
    $key_07bb = { 54 d4 [2] 70 da [2] 5b f6 [2] 75 d4 [2] 61 cf [2] 6e d5 [2] 70 c8 [2] 72 c9 [2] 69 cf [2] 75 c8 [2] 69 e7 }

  condition:
    any of them
}