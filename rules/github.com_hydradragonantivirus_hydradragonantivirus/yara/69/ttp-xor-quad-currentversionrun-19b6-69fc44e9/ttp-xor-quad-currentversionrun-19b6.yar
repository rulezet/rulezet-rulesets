rule TTP_XOR_QUAD_CurrentVersionRun_19b6 {
  strings:
    $key_19b6 = { 4a d9 [2] 6e d7 [2] 45 fb [2] 6b d9 [2] 7f c2 [2] 70 d8 [2] 6e c5 [2] 6c c4 [2] 77 c2 [2] 6b c5 [2] 77 ea }

  condition:
    any of them
}