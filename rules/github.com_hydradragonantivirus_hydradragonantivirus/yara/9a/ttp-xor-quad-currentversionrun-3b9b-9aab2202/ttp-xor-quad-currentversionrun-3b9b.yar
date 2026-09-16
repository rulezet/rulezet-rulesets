rule TTP_XOR_QUAD_CurrentVersionRun_3b9b {
  strings:
    $key_3b9b = { 68 f4 [2] 4c fa [2] 67 d6 [2] 49 f4 [2] 5d ef [2] 52 f5 [2] 4c e8 [2] 4e e9 [2] 55 ef [2] 49 e8 [2] 55 c7 }

  condition:
    any of them
}