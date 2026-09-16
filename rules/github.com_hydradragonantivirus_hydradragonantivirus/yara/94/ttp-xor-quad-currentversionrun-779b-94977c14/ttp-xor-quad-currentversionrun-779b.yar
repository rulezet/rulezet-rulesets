rule TTP_XOR_QUAD_CurrentVersionRun_779b {
  strings:
    $key_779b = { 24 f4 [2] 00 fa [2] 2b d6 [2] 05 f4 [2] 11 ef [2] 1e f5 [2] 00 e8 [2] 02 e9 [2] 19 ef [2] 05 e8 [2] 19 c7 }

  condition:
    any of them
}