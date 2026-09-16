rule TTP_XOR_QUAD_CurrentVersionRun_e9b6 {
  strings:
    $key_e9b6 = { ba d9 [2] 9e d7 [2] b5 fb [2] 9b d9 [2] 8f c2 [2] 80 d8 [2] 9e c5 [2] 9c c4 [2] 87 c2 [2] 9b c5 [2] 87 ea }

  condition:
    any of them
}