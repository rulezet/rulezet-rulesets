rule TTP_XOR_QUAD_CurrentVersionRun_79b6 {
  strings:
    $key_79b6 = { 2a d9 [2] 0e d7 [2] 25 fb [2] 0b d9 [2] 1f c2 [2] 10 d8 [2] 0e c5 [2] 0c c4 [2] 17 c2 [2] 0b c5 [2] 17 ea }

  condition:
    any of them
}