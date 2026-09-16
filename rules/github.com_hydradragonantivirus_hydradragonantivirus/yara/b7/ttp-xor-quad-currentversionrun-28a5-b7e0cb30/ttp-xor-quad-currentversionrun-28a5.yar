rule TTP_XOR_QUAD_CurrentVersionRun_28a5 {
  strings:
    $key_28a5 = { 7b ca [2] 5f c4 [2] 74 e8 [2] 5a ca [2] 4e d1 [2] 41 cb [2] 5f d6 [2] 5d d7 [2] 46 d1 [2] 5a d6 [2] 46 f9 }

  condition:
    any of them
}