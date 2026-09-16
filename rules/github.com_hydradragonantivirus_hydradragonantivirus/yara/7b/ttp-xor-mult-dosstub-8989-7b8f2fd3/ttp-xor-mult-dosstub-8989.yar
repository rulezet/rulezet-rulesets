rule TTP_XOR_MULT_DOSStub_8989 {
  strings:
    $key_8989 = { dd e1 [2] a9 f9 [2] ee fb [2] a9 ea [2] e7 e6 [2] eb ec [2] fc e7 [2] e7 a9 [2] da }

  condition:
    any of them
}