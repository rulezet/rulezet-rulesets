rule TTP_XOR_QUAD_CurrentVersionRun_339b {
  strings:
    $key_339b = { 60 f4 [2] 44 fa [2] 6f d6 [2] 41 f4 [2] 55 ef [2] 5a f5 [2] 44 e8 [2] 46 e9 [2] 5d ef [2] 41 e8 [2] 5d c7 }

  condition:
    any of them
}