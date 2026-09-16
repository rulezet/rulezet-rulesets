rule TTP_XOR_MULT_DOSStub_a78f {
  strings:
    $key_a78f = { f3 e7 [2] 87 ff [2] c0 fd [2] 87 ec [2] c9 e0 [2] c5 ea [2] d2 e1 [2] c9 af [2] f4 }

  condition:
    any of them
}