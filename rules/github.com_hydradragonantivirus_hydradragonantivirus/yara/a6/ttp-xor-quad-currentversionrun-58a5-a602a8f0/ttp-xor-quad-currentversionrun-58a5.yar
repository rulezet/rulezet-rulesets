rule TTP_XOR_QUAD_CurrentVersionRun_58a5 {
  strings:
    $key_58a5 = { 0b ca [2] 2f c4 [2] 04 e8 [2] 2a ca [2] 3e d1 [2] 31 cb [2] 2f d6 [2] 2d d7 [2] 36 d1 [2] 2a d6 [2] 36 f9 }

  condition:
    any of them
}