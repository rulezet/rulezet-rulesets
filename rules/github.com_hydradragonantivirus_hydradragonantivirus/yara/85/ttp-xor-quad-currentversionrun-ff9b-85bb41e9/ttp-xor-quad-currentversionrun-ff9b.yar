rule TTP_XOR_QUAD_CurrentVersionRun_ff9b {
  strings:
    $key_ff9b = { ac f4 [2] 88 fa [2] a3 d6 [2] 8d f4 [2] 99 ef [2] 96 f5 [2] 88 e8 [2] 8a e9 [2] 91 ef [2] 8d e8 [2] 91 c7 }

  condition:
    any of them
}