rule TTP_XOR_QUAD_CurrentVersionRun_59bb {
  strings:
    $key_59bb = { 0a d4 [2] 2e da [2] 05 f6 [2] 2b d4 [2] 3f cf [2] 30 d5 [2] 2e c8 [2] 2c c9 [2] 37 cf [2] 2b c8 [2] 37 e7 }

  condition:
    any of them
}