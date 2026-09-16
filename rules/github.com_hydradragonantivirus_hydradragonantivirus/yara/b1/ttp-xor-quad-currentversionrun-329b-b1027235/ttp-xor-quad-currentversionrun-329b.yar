rule TTP_XOR_QUAD_CurrentVersionRun_329b {
  strings:
    $key_329b = { 61 f4 [2] 45 fa [2] 6e d6 [2] 40 f4 [2] 54 ef [2] 5b f5 [2] 45 e8 [2] 47 e9 [2] 5c ef [2] 40 e8 [2] 5c c7 }

  condition:
    any of them
}