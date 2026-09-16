rule TTP_XOR_MULT_DOSStub_848f {
  strings:
    $key_848f = { d0 e7 [2] a4 ff [2] e3 fd [2] a4 ec [2] ea e0 [2] e6 ea [2] f1 e1 [2] ea af [2] d7 }

  condition:
    any of them
}