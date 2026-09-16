rule TTP_XOR_QUAD_CurrentVersionRun_639b {
  strings:
    $key_639b = { 30 f4 [2] 14 fa [2] 3f d6 [2] 11 f4 [2] 05 ef [2] 0a f5 [2] 14 e8 [2] 16 e9 [2] 0d ef [2] 11 e8 [2] 0d c7 }

  condition:
    any of them
}