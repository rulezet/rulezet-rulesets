rule TTP_XOR_MULT_DOSStub_87d5 {
  strings:
    $key_87d5 = { d3 bd [2] a7 a5 [2] e0 a7 [2] a7 b6 [2] e9 ba [2] e5 b0 [2] f2 bb [2] e9 f5 [2] d4 }

  condition:
    any of them
}