rule TTP_XOR_QUAD_CurrentVersionRun_4db6 {
  strings:
    $key_4db6 = { 1e d9 [2] 3a d7 [2] 11 fb [2] 3f d9 [2] 2b c2 [2] 24 d8 [2] 3a c5 [2] 38 c4 [2] 23 c2 [2] 3f c5 [2] 23 ea }

  condition:
    any of them
}