rule TTP_XOR_QUAD_CurrentVersionRun_7d9b {
  strings:
    $key_7d9b = { 2e f4 [2] 0a fa [2] 21 d6 [2] 0f f4 [2] 1b ef [2] 14 f5 [2] 0a e8 [2] 08 e9 [2] 13 ef [2] 0f e8 [2] 13 c7 }

  condition:
    any of them
}