rule TTP_XOR_MULT_DOSStub_b486 {
  strings:
    $key_b486 = { e0 ee [2] 94 f6 [2] d3 f4 [2] 94 e5 [2] da e9 [2] d6 e3 [2] c1 e8 [2] da a6 [2] e7 }

  condition:
    any of them
}