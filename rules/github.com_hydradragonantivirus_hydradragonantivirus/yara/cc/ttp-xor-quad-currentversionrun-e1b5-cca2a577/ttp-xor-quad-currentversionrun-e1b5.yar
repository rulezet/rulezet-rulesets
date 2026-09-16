rule TTP_XOR_QUAD_CurrentVersionRun_e1b5 {
  strings:
    $key_e1b5 = { b2 da [2] 96 d4 [2] bd f8 [2] 93 da [2] 87 c1 [2] 88 db [2] 96 c6 [2] 94 c7 [2] 8f c1 [2] 93 c6 [2] 8f e9 }

  condition:
    any of them
}