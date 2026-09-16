rule TTP_XOR_QUAD_CurrentVersionRun_49b6 {
  strings:
    $key_49b6 = { 1a d9 [2] 3e d7 [2] 15 fb [2] 3b d9 [2] 2f c2 [2] 20 d8 [2] 3e c5 [2] 3c c4 [2] 27 c2 [2] 3b c5 [2] 27 ea }

  condition:
    any of them
}