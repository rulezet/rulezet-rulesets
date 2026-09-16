rule TTP_XOR_QUAD_CurrentVersionRun_0db6 {
  strings:
    $key_0db6 = { 5e d9 [2] 7a d7 [2] 51 fb [2] 7f d9 [2] 6b c2 [2] 64 d8 [2] 7a c5 [2] 78 c4 [2] 63 c2 [2] 7f c5 [2] 63 ea }

  condition:
    any of them
}