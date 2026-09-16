rule TTP_XOR_QUAD_CurrentVersionRun_71bb {
  strings:
    $key_71bb = { 22 d4 [2] 06 da [2] 2d f6 [2] 03 d4 [2] 17 cf [2] 18 d5 [2] 06 c8 [2] 04 c9 [2] 1f cf [2] 03 c8 [2] 1f e7 }

  condition:
    any of them
}