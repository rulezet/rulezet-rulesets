rule TTP_XOR_QUAD_CurrentVersionRun_09a5 {
  strings:
    $key_09a5 = { 5a ca [2] 7e c4 [2] 55 e8 [2] 7b ca [2] 6f d1 [2] 60 cb [2] 7e d6 [2] 7c d7 [2] 67 d1 [2] 7b d6 [2] 67 f9 }

  condition:
    any of them
}