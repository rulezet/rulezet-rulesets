rule TTP_XOR_QUAD_CurrentVersionRun_75bb {
  strings:
    $key_75bb = { 26 d4 [2] 02 da [2] 29 f6 [2] 07 d4 [2] 13 cf [2] 1c d5 [2] 02 c8 [2] 00 c9 [2] 1b cf [2] 07 c8 [2] 1b e7 }

  condition:
    any of them
}