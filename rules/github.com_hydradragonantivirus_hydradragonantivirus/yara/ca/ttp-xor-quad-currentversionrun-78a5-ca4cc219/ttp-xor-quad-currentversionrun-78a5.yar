rule TTP_XOR_QUAD_CurrentVersionRun_78a5 {
  strings:
    $key_78a5 = { 2b ca [2] 0f c4 [2] 24 e8 [2] 0a ca [2] 1e d1 [2] 11 cb [2] 0f d6 [2] 0d d7 [2] 16 d1 [2] 0a d6 [2] 16 f9 }

  condition:
    any of them
}