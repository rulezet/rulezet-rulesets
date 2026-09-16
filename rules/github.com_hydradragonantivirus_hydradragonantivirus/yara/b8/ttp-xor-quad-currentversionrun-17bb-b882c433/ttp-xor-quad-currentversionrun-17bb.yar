rule TTP_XOR_QUAD_CurrentVersionRun_17bb {
  strings:
    $key_17bb = { 44 d4 [2] 60 da [2] 4b f6 [2] 65 d4 [2] 71 cf [2] 7e d5 [2] 60 c8 [2] 62 c9 [2] 79 cf [2] 65 c8 [2] 79 e7 }

  condition:
    any of them
}