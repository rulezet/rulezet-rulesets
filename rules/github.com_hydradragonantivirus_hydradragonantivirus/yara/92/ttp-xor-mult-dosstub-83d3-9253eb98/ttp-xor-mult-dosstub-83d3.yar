rule TTP_XOR_MULT_DOSStub_83d3 {
  strings:
    $key_83d3 = { d7 bb [2] a3 a3 [2] e4 a1 [2] a3 b0 [2] ed bc [2] e1 b6 [2] f6 bd [2] ed f3 [2] d0 }

  condition:
    any of them
}