rule TTP_XOR_MULT_DOSStub_b48f {
  strings:
    $key_b48f = { e0 e7 [2] 94 ff [2] d3 fd [2] 94 ec [2] da e0 [2] d6 ea [2] c1 e1 [2] da af [2] e7 }

  condition:
    any of them
}