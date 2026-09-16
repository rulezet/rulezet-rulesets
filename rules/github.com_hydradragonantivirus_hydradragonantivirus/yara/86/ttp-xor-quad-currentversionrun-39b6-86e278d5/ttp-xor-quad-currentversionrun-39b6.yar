rule TTP_XOR_QUAD_CurrentVersionRun_39b6 {
  strings:
    $key_39b6 = { 6a d9 [2] 4e d7 [2] 65 fb [2] 4b d9 [2] 5f c2 [2] 50 d8 [2] 4e c5 [2] 4c c4 [2] 57 c2 [2] 4b c5 [2] 57 ea }

  condition:
    any of them
}