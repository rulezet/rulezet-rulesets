rule TTP_XOR_QUAD_CurrentVersionRun_f8a6 {
  strings:
    $key_f8a6 = { ab c9 [2] 8f c7 [2] a4 eb [2] 8a c9 [2] 9e d2 [2] 91 c8 [2] 8f d5 [2] 8d d4 [2] 96 d2 [2] 8a d5 [2] 96 fa }

  condition:
    any of them
}