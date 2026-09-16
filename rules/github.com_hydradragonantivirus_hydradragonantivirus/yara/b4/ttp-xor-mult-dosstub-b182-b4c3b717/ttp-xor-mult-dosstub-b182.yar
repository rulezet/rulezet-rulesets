rule TTP_XOR_MULT_DOSStub_b182 {
  strings:
    $key_b182 = { e5 ea [2] 91 f2 [2] d6 f0 [2] 91 e1 [2] df ed [2] d3 e7 [2] c4 ec [2] df a2 [2] e2 }

  condition:
    any of them
}