rule TTP_XOR_QUAD_CurrentVersionRun_4d9b {
  strings:
    $key_4d9b = { 1e f4 [2] 3a fa [2] 11 d6 [2] 3f f4 [2] 2b ef [2] 24 f5 [2] 3a e8 [2] 38 e9 [2] 23 ef [2] 3f e8 [2] 23 c7 }

  condition:
    any of them
}