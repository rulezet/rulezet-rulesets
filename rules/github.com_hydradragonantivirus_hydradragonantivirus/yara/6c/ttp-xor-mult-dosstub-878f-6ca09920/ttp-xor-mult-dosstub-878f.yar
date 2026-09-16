rule TTP_XOR_MULT_DOSStub_878f {
  strings:
    $key_878f = { d3 e7 [2] a7 ff [2] e0 fd [2] a7 ec [2] e9 e0 [2] e5 ea [2] f2 e1 [2] e9 af [2] d4 }

  condition:
    any of them
}