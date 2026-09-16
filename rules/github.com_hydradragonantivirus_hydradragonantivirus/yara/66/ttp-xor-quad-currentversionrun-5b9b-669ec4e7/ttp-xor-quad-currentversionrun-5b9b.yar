rule TTP_XOR_QUAD_CurrentVersionRun_5b9b {
  strings:
    $key_5b9b = { 08 f4 [2] 2c fa [2] 07 d6 [2] 29 f4 [2] 3d ef [2] 32 f5 [2] 2c e8 [2] 2e e9 [2] 35 ef [2] 29 e8 [2] 35 c7 }

  condition:
    any of them
}