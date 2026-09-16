rule TTP_XOR_QUAD_CurrentVersionRun_29a5 {
  strings:
    $key_29a5 = { 7a ca [2] 5e c4 [2] 75 e8 [2] 5b ca [2] 4f d1 [2] 40 cb [2] 5e d6 [2] 5c d7 [2] 47 d1 [2] 5b d6 [2] 47 f9 }

  condition:
    any of them
}