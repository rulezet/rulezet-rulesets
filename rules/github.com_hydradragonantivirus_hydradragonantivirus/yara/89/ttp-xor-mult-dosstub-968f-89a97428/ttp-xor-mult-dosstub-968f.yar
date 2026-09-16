rule TTP_XOR_MULT_DOSStub_968f {
  strings:
    $key_968f = { c2 e7 [2] b6 ff [2] f1 fd [2] b6 ec [2] f8 e0 [2] f4 ea [2] e3 e1 [2] f8 af [2] c5 }

  condition:
    any of them
}