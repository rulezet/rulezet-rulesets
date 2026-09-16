rule TTP_XOR_QUAD_CurrentVersionRun_7ebb {
  strings:
    $key_7ebb = { 2d d4 [2] 09 da [2] 22 f6 [2] 0c d4 [2] 18 cf [2] 17 d5 [2] 09 c8 [2] 0b c9 [2] 10 cf [2] 0c c8 [2] 10 e7 }

  condition:
    any of them
}