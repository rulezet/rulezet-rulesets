rule TTP_XOR_QUAD_CurrentVersionRun_569b {
  strings:
    $key_569b = { 05 f4 [2] 21 fa [2] 0a d6 [2] 24 f4 [2] 30 ef [2] 3f f5 [2] 21 e8 [2] 23 e9 [2] 38 ef [2] 24 e8 [2] 38 c7 }

  condition:
    any of them
}