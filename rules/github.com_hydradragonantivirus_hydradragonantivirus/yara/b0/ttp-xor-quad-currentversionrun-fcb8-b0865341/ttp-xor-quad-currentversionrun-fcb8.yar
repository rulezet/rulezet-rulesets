rule TTP_XOR_QUAD_CurrentVersionRun_fcb8 {
  strings:
    $key_fcb8 = { af d7 [2] 8b d9 [2] a0 f5 [2] 8e d7 [2] 9a cc [2] 95 d6 [2] 8b cb [2] 89 ca [2] 92 cc [2] 8e cb [2] 92 e4 }

  condition:
    any of them
}