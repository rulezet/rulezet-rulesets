rule TTP_XOR_QUAD_CurrentVersionRun_79a5 {
  strings:
    $key_79a5 = { 2a ca [2] 0e c4 [2] 25 e8 [2] 0b ca [2] 1f d1 [2] 10 cb [2] 0e d6 [2] 0c d7 [2] 17 d1 [2] 0b d6 [2] 17 f9 }

  condition:
    any of them
}