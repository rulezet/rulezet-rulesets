rule TTP_XOR_QUAD_CurrentVersionRun_799b {
  strings:
    $key_799b = { 2a f4 [2] 0e fa [2] 25 d6 [2] 0b f4 [2] 1f ef [2] 10 f5 [2] 0e e8 [2] 0c e9 [2] 17 ef [2] 0b e8 [2] 17 c7 }

  condition:
    any of them
}