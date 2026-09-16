rule TTP_XOR_QUAD_CurrentVersionRun_609b {
  strings:
    $key_609b = { 33 f4 [2] 17 fa [2] 3c d6 [2] 12 f4 [2] 06 ef [2] 09 f5 [2] 17 e8 [2] 15 e9 [2] 0e ef [2] 12 e8 [2] 0e c7 }

  condition:
    any of them
}