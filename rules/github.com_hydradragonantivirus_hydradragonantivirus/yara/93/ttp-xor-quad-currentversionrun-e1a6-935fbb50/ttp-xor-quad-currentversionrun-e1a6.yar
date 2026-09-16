rule TTP_XOR_QUAD_CurrentVersionRun_e1a6 {
  strings:
    $key_e1a6 = { b2 c9 [2] 96 c7 [2] bd eb [2] 93 c9 [2] 87 d2 [2] 88 c8 [2] 96 d5 [2] 94 d4 [2] 8f d2 [2] 93 d5 [2] 8f fa }

  condition:
    any of them
}