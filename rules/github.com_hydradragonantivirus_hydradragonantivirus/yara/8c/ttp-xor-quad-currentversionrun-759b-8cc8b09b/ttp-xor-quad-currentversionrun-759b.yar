rule TTP_XOR_QUAD_CurrentVersionRun_759b {
  strings:
    $key_759b = { 26 f4 [2] 02 fa [2] 29 d6 [2] 07 f4 [2] 13 ef [2] 1c f5 [2] 02 e8 [2] 00 e9 [2] 1b ef [2] 07 e8 [2] 1b c7 }

  condition:
    any of them
}