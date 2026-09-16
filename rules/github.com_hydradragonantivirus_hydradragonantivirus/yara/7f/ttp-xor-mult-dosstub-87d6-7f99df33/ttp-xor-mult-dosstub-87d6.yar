rule TTP_XOR_MULT_DOSStub_87d6 {
  strings:
    $key_87d6 = { d3 be [2] a7 a6 [2] e0 a4 [2] a7 b5 [2] e9 b9 [2] e5 b3 [2] f2 b8 [2] e9 f6 [2] d4 }

  condition:
    any of them
}