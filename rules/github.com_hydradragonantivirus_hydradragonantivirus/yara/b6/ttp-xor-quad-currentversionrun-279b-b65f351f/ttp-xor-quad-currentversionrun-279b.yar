rule TTP_XOR_QUAD_CurrentVersionRun_279b {
  strings:
    $key_279b = { 74 f4 [2] 50 fa [2] 7b d6 [2] 55 f4 [2] 41 ef [2] 4e f5 [2] 50 e8 [2] 52 e9 [2] 49 ef [2] 55 e8 [2] 49 c7 }

  condition:
    any of them
}