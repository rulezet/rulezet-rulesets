rule TTP_XOR_QUAD_CurrentVersionRun_68b6 {
  strings:
    $key_68b6 = { 3b d9 [2] 1f d7 [2] 34 fb [2] 1a d9 [2] 0e c2 [2] 01 d8 [2] 1f c5 [2] 1d c4 [2] 06 c2 [2] 1a c5 [2] 06 ea }

  condition:
    any of them
}