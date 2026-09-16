rule TTP_XOR_QUAD_CurrentVersionRun_7b9b {
  strings:
    $key_7b9b = { 28 f4 [2] 0c fa [2] 27 d6 [2] 09 f4 [2] 1d ef [2] 12 f5 [2] 0c e8 [2] 0e e9 [2] 15 ef [2] 09 e8 [2] 15 c7 }

  condition:
    any of them
}