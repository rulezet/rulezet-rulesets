rule TTP_XOR_QUAD_CurrentVersionRun_579b {
  strings:
    $key_579b = { 04 f4 [2] 20 fa [2] 0b d6 [2] 25 f4 [2] 31 ef [2] 3e f5 [2] 20 e8 [2] 22 e9 [2] 39 ef [2] 25 e8 [2] 39 c7 }

  condition:
    any of them
}