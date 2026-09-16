rule TTP_XOR_MULT_DOSStub_818f {
  strings:
    $key_818f = { d5 e7 [2] a1 ff [2] e6 fd [2] a1 ec [2] ef e0 [2] e3 ea [2] f4 e1 [2] ef af [2] d2 }

  condition:
    any of them
}