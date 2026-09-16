rule TTP_XOR_MULT_DOSStub_d0d3 {
  strings:
    $key_d0d3 = { 84 bb [2] f0 a3 [2] b7 a1 [2] f0 b0 [2] be bc [2] b2 b6 [2] a5 bd [2] be f3 [2] 83 }

  condition:
    any of them
}