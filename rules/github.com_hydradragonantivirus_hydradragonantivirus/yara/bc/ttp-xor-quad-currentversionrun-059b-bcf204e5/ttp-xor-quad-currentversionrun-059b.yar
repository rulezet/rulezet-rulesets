rule TTP_XOR_QUAD_CurrentVersionRun_059b {
  strings:
    $key_059b = { 56 f4 [2] 72 fa [2] 59 d6 [2] 77 f4 [2] 63 ef [2] 6c f5 [2] 72 e8 [2] 70 e9 [2] 6b ef [2] 77 e8 [2] 6b c7 }

  condition:
    any of them
}