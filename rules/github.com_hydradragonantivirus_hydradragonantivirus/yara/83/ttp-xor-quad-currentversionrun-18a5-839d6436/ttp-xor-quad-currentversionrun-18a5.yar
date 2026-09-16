rule TTP_XOR_QUAD_CurrentVersionRun_18a5 {
  strings:
    $key_18a5 = { 4b ca [2] 6f c4 [2] 44 e8 [2] 6a ca [2] 7e d1 [2] 71 cb [2] 6f d6 [2] 6d d7 [2] 76 d1 [2] 6a d6 [2] 76 f9 }

  condition:
    any of them
}