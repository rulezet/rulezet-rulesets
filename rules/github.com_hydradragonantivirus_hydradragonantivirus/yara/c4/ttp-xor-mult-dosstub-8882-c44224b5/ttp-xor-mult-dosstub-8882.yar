rule TTP_XOR_MULT_DOSStub_8882 {
  strings:
    $key_8882 = { dc ea [2] a8 f2 [2] ef f0 [2] a8 e1 [2] e6 ed [2] ea e7 [2] fd ec [2] e6 a2 [2] db }

  condition:
    any of them
}