rule TTP_XOR_QUAD_CurrentVersionRun_08a5 {
  strings:
    $key_08a5 = { 5b ca [2] 7f c4 [2] 54 e8 [2] 7a ca [2] 6e d1 [2] 61 cb [2] 7f d6 [2] 7d d7 [2] 66 d1 [2] 7a d6 [2] 66 f9 }

  condition:
    any of them
}