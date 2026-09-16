rule TTP_XOR_QUAD_CurrentVersionRun_e1b4 {
  strings:
    $key_e1b4 = { b2 db [2] 96 d5 [2] bd f9 [2] 93 db [2] 87 c0 [2] 88 da [2] 96 c7 [2] 94 c6 [2] 8f c0 [2] 93 c7 [2] 8f e8 }

  condition:
    any of them
}