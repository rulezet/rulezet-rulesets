rule TTP_XOR_QUAD_CurrentVersionRun_0ebb {
  strings:
    $key_0ebb = { 5d d4 [2] 79 da [2] 52 f6 [2] 7c d4 [2] 68 cf [2] 67 d5 [2] 79 c8 [2] 7b c9 [2] 60 cf [2] 7c c8 [2] 60 e7 }

  condition:
    any of them
}