rule TTP_XOR_QUAD_CurrentVersionRun_1b9b {
  strings:
    $key_1b9b = { 48 f4 [2] 6c fa [2] 47 d6 [2] 69 f4 [2] 7d ef [2] 72 f5 [2] 6c e8 [2] 6e e9 [2] 75 ef [2] 69 e8 [2] 75 c7 }

  condition:
    any of them
}