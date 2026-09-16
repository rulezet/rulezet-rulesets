rule TTP_XOR_QUAD_CurrentVersionRun_25bb {
  strings:
    $key_25bb = { 76 d4 [2] 52 da [2] 79 f6 [2] 57 d4 [2] 43 cf [2] 4c d5 [2] 52 c8 [2] 50 c9 [2] 4b cf [2] 57 c8 [2] 4b e7 }

  condition:
    any of them
}