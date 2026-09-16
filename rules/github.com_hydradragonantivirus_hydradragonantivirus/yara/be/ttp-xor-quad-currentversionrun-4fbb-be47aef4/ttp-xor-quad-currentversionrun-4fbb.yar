rule TTP_XOR_QUAD_CurrentVersionRun_4fbb {
  strings:
    $key_4fbb = { 1c d4 [2] 38 da [2] 13 f6 [2] 3d d4 [2] 29 cf [2] 26 d5 [2] 38 c8 [2] 3a c9 [2] 21 cf [2] 3d c8 [2] 21 e7 }

  condition:
    any of them
}