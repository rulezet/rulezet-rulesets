rule TTP_XOR_QUAD_CurrentVersionRun_69bb {
  strings:
    $key_69bb = { 3a d4 [2] 1e da [2] 35 f6 [2] 1b d4 [2] 0f cf [2] 00 d5 [2] 1e c8 [2] 1c c9 [2] 07 cf [2] 1b c8 [2] 07 e7 }

  condition:
    any of them
}