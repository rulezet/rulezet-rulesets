rule TTP_XOR_QUAD_CurrentVersionRun_67bb {
  strings:
    $key_67bb = { 34 d4 [2] 10 da [2] 3b f6 [2] 15 d4 [2] 01 cf [2] 0e d5 [2] 10 c8 [2] 12 c9 [2] 09 cf [2] 15 c8 [2] 09 e7 }

  condition:
    any of them
}