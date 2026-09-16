rule TTP_XOR_MULT_DOSStub_87d9 {
  strings:
    $key_87d9 = { d3 b1 [2] a7 a9 [2] e0 ab [2] a7 ba [2] e9 b6 [2] e5 bc [2] f2 b7 [2] e9 f9 [2] d4 }

  condition:
    any of them
}