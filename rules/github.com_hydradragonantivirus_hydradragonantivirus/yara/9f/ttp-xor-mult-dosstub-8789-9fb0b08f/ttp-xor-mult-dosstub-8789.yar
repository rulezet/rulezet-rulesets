rule TTP_XOR_MULT_DOSStub_8789 {
  strings:
    $key_8789 = { d3 e1 [2] a7 f9 [2] e0 fb [2] a7 ea [2] e9 e6 [2] e5 ec [2] f2 e7 [2] e9 a9 [2] d4 }

  condition:
    any of them
}