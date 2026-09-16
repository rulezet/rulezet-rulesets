rule TTP_XOR_QUAD_CurrentVersionRun_38b6 {
  strings:
    $key_38b6 = { 6b d9 [2] 4f d7 [2] 64 fb [2] 4a d9 [2] 5e c2 [2] 51 d8 [2] 4f c5 [2] 4d c4 [2] 56 c2 [2] 4a c5 [2] 56 ea }

  condition:
    any of them
}