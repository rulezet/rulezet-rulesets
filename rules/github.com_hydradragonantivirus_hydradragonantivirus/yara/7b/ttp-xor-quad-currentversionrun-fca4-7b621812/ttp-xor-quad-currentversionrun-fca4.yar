rule TTP_XOR_QUAD_CurrentVersionRun_fca4 {
  strings:
    $key_fca4 = { af cb [2] 8b c5 [2] a0 e9 [2] 8e cb [2] 9a d0 [2] 95 ca [2] 8b d7 [2] 89 d6 [2] 92 d0 [2] 8e d7 [2] 92 f8 }

  condition:
    any of them
}