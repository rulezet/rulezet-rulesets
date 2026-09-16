rule TTP_XOR_QUAD_CurrentVersionRun_f5bb {
  strings:
    $key_f5bb = { a6 d4 [2] 82 da [2] a9 f6 [2] 87 d4 [2] 93 cf [2] 9c d5 [2] 82 c8 [2] 80 c9 [2] 9b cf [2] 87 c8 [2] 9b e7 }

  condition:
    any of them
}