rule TTP_XOR_QUAD_CurrentVersionRun_fab0 {
  strings:
    $key_fab0 = { a9 df [2] 8d d1 [2] a6 fd [2] 88 df [2] 9c c4 [2] 93 de [2] 8d c3 [2] 8f c2 [2] 94 c4 [2] 88 c3 [2] 94 ec }

  condition:
    any of them
}