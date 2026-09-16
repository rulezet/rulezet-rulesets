rule TTP_XOR_QUAD_CurrentVersionRun_7db6 {
  strings:
    $key_7db6 = { 2e d9 [2] 0a d7 [2] 21 fb [2] 0f d9 [2] 1b c2 [2] 14 d8 [2] 0a c5 [2] 08 c4 [2] 13 c2 [2] 0f c5 [2] 13 ea }

  condition:
    any of them
}