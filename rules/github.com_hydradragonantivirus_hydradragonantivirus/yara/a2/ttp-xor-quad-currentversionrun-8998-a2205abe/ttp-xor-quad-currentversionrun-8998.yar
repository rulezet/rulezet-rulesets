rule TTP_XOR_QUAD_CurrentVersionRun_8998 {
  strings:
    $key_8998 = { da f7 [2] fe f9 [2] d5 d5 [2] fb f7 [2] ef ec [2] e0 f6 [2] fe eb [2] fc ea [2] e7 ec [2] fb eb [2] e7 c4 }

  condition:
    any of them
}