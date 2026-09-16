rule TTP_XOR_QUAD_CurrentVersionRun_77bb {
  strings:
    $key_77bb = { 24 d4 [2] 00 da [2] 2b f6 [2] 05 d4 [2] 11 cf [2] 1e d5 [2] 00 c8 [2] 02 c9 [2] 19 cf [2] 05 c8 [2] 19 e7 }

  condition:
    any of them
}