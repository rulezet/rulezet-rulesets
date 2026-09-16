rule TTP_XOR_MULT_DOSStub_b5c5 {
  strings:
    $key_b5c5 = { e1 ad [2] 95 b5 [2] d2 b7 [2] 95 a6 [2] db aa [2] d7 a0 [2] c0 ab [2] db e5 [2] e6 }

  condition:
    any of them
}