rule TTP_XOR_QUAD_CurrentVersionRun_57bb {
  strings:
    $key_57bb = { 04 d4 [2] 20 da [2] 0b f6 [2] 25 d4 [2] 31 cf [2] 3e d5 [2] 20 c8 [2] 22 c9 [2] 39 cf [2] 25 c8 [2] 39 e7 }

  condition:
    any of them
}