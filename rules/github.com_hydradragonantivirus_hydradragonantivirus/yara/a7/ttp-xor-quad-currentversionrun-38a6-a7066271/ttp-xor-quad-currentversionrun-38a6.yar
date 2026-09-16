rule TTP_XOR_QUAD_CurrentVersionRun_38a6 {
  strings:
    $key_38a6 = { 6b c9 [2] 4f c7 [2] 64 eb [2] 4a c9 [2] 5e d2 [2] 51 c8 [2] 4f d5 [2] 4d d4 [2] 56 d2 [2] 4a d5 [2] 56 fa }

  condition:
    any of them
}