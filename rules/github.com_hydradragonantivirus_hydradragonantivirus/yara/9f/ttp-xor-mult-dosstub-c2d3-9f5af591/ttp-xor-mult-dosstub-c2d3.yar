rule TTP_XOR_MULT_DOSStub_c2d3 {
  strings:
    $key_c2d3 = { 96 bb [2] e2 a3 [2] a5 a1 [2] e2 b0 [2] ac bc [2] a0 b6 [2] b7 bd [2] ac f3 [2] 91 }

  condition:
    any of them
}