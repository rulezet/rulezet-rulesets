rule TTP_XOR_MULT_DOSStub_978f {
  strings:
    $key_978f = { c3 e7 [2] b7 ff [2] f0 fd [2] b7 ec [2] f9 e0 [2] f5 ea [2] e2 e1 [2] f9 af [2] c4 }

  condition:
    any of them
}