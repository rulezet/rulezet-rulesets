rule TTP_XOR_QUAD_CurrentVersionRun_53bb {
  strings:
    $key_53bb = { 00 d4 [2] 24 da [2] 0f f6 [2] 21 d4 [2] 35 cf [2] 3a d5 [2] 24 c8 [2] 26 c9 [2] 3d cf [2] 21 c8 [2] 3d e7 }

  condition:
    any of them
}