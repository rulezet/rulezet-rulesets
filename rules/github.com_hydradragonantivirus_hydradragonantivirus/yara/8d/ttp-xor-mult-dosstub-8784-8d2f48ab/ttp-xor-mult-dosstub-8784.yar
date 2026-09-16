rule TTP_XOR_MULT_DOSStub_8784 {
  strings:
    $key_8784 = { d3 ec [2] a7 f4 [2] e0 f6 [2] a7 e7 [2] e9 eb [2] e5 e1 [2] f2 ea [2] e9 a4 [2] d4 }

  condition:
    any of them
}