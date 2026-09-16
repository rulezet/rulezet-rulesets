rule TTP_XOR_QUAD_CurrentVersionRun_2fbb {
  strings:
    $key_2fbb = { 7c d4 [2] 58 da [2] 73 f6 [2] 5d d4 [2] 49 cf [2] 46 d5 [2] 58 c8 [2] 5a c9 [2] 41 cf [2] 5d c8 [2] 41 e7 }

  condition:
    any of them
}