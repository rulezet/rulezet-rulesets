rule TTP_XOR_QUAD_CurrentVersionRun_0fbb {
  strings:
    $key_0fbb = { 5c d4 [2] 78 da [2] 53 f6 [2] 7d d4 [2] 69 cf [2] 66 d5 [2] 78 c8 [2] 7a c9 [2] 61 cf [2] 7d c8 [2] 61 e7 }

  condition:
    any of them
}