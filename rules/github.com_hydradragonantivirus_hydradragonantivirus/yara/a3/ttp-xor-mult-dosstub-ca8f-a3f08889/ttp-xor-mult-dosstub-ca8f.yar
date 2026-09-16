rule TTP_XOR_MULT_DOSStub_ca8f {
  strings:
    $key_ca8f = { 9e e7 [2] ea ff [2] ad fd [2] ea ec [2] a4 e0 [2] a8 ea [2] bf e1 [2] a4 af [2] 99 }

  condition:
    any of them
}