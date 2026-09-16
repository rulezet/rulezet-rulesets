rule TTP_XOR_QUAD_CurrentVersionRun_1fbb {
  strings:
    $key_1fbb = { 4c d4 [2] 68 da [2] 43 f6 [2] 6d d4 [2] 79 cf [2] 76 d5 [2] 68 c8 [2] 6a c9 [2] 71 cf [2] 6d c8 [2] 71 e7 }

  condition:
    any of them
}