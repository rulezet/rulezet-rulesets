rule TTP_XOR_QUAD_CurrentVersionRun_69b6 {
  strings:
    $key_69b6 = { 3a d9 [2] 1e d7 [2] 35 fb [2] 1b d9 [2] 0f c2 [2] 00 d8 [2] 1e c5 [2] 1c c4 [2] 07 c2 [2] 1b c5 [2] 07 ea }

  condition:
    any of them
}