rule TTP_XOR_QUAD_CurrentVersionRun_78b6 {
  strings:
    $key_78b6 = { 2b d9 [2] 0f d7 [2] 24 fb [2] 0a d9 [2] 1e c2 [2] 11 d8 [2] 0f c5 [2] 0d c4 [2] 16 c2 [2] 0a c5 [2] 16 ea }

  condition:
    any of them
}