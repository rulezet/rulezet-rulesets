rule TTP_XOR_MULT_DOSStub_b2c7 {
  strings:
    $key_b2c7 = { e6 af [2] 92 b7 [2] d5 b5 [2] 92 a4 [2] dc a8 [2] d0 a2 [2] c7 a9 [2] dc e7 [2] e1 }

  condition:
    any of them
}