rule TTP_XOR_QUAD_CurrentVersionRun_409b {
  strings:
    $key_409b = { 13 f4 [2] 37 fa [2] 1c d6 [2] 32 f4 [2] 26 ef [2] 29 f5 [2] 37 e8 [2] 35 e9 [2] 2e ef [2] 32 e8 [2] 2e c7 }

  condition:
    any of them
}