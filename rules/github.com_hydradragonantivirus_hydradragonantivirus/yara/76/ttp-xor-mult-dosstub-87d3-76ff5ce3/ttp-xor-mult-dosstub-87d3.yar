rule TTP_XOR_MULT_DOSStub_87d3 {
  strings:
    $key_87d3 = { d3 bb [2] a7 a3 [2] e0 a1 [2] a7 b0 [2] e9 bc [2] e5 b6 [2] f2 bd [2] e9 f3 [2] d4 }

  condition:
    any of them
}