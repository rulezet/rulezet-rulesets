rule TTP_XOR_QUAD_CurrentVersionRun_2d9b {
  strings:
    $key_2d9b = { 7e f4 [2] 5a fa [2] 71 d6 [2] 5f f4 [2] 4b ef [2] 44 f5 [2] 5a e8 [2] 58 e9 [2] 43 ef [2] 5f e8 [2] 43 c7 }

  condition:
    any of them
}