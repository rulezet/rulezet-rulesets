rule TTP_XOR_MULT_DOSStub_b4c7 {
  strings:
    $key_b4c7 = { e0 af [2] 94 b7 [2] d3 b5 [2] 94 a4 [2] da a8 [2] d6 a2 [2] c1 a9 [2] da e7 [2] e7 }

  condition:
    any of them
}