rule TTP_XOR_MULT_DOSStub_c2d5 {
  strings:
    $key_c2d5 = { 96 bd [2] e2 a5 [2] a5 a7 [2] e2 b6 [2] ac ba [2] a0 b0 [2] b7 bb [2] ac f5 [2] 91 }

  condition:
    any of them
}