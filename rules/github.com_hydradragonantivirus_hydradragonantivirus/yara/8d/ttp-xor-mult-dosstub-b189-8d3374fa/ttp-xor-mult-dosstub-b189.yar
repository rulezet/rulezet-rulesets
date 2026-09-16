rule TTP_XOR_MULT_DOSStub_b189 {
  strings:
    $key_b189 = { e5 e1 [2] 91 f9 [2] d6 fb [2] 91 ea [2] df e6 [2] d3 ec [2] c4 e7 [2] df a9 [2] e2 }

  condition:
    any of them
}