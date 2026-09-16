rule TTP_XOR_QUAD_CurrentVersionRun_41bb {
  strings:
    $key_41bb = { 12 d4 [2] 36 da [2] 1d f6 [2] 33 d4 [2] 27 cf [2] 28 d5 [2] 36 c8 [2] 34 c9 [2] 2f cf [2] 33 c8 [2] 2f e7 }

  condition:
    any of them
}