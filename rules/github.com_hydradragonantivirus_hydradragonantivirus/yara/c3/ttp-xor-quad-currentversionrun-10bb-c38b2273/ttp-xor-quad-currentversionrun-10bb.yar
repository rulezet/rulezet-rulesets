rule TTP_XOR_QUAD_CurrentVersionRun_10bb {
  strings:
    $key_10bb = { 43 d4 [2] 67 da [2] 4c f6 [2] 62 d4 [2] 76 cf [2] 79 d5 [2] 67 c8 [2] 65 c9 [2] 7e cf [2] 62 c8 [2] 7e e7 }

  condition:
    any of them
}