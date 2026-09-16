rule TTP_XOR_QUAD_CurrentVersionRun_0cb6 {
  strings:
    $key_0cb6 = { 5f d9 [2] 7b d7 [2] 50 fb [2] 7e d9 [2] 6a c2 [2] 65 d8 [2] 7b c5 [2] 79 c4 [2] 62 c2 [2] 7e c5 [2] 62 ea }

  condition:
    any of them
}