rule TTP_XOR_QUAD_CurrentVersionRun_0d9b {
  strings:
    $key_0d9b = { 5e f4 [2] 7a fa [2] 51 d6 [2] 7f f4 [2] 6b ef [2] 64 f5 [2] 7a e8 [2] 78 e9 [2] 63 ef [2] 7f e8 [2] 63 c7 }

  condition:
    any of them
}