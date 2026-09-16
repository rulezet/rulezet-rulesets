rule TTP_XOR_MULT_DOSStub_a68f {
  strings:
    $key_a68f = { f2 e7 [2] 86 ff [2] c1 fd [2] 86 ec [2] c8 e0 [2] c4 ea [2] d3 e1 [2] c8 af [2] f5 }

  condition:
    any of them
}