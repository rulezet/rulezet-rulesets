rule TTP_XOR_MULT_DOSStub_c5d5 {
  strings:
    $key_c5d5 = { 91 bd [2] e5 a5 [2] a2 a7 [2] e5 b6 [2] ab ba [2] a7 b0 [2] b0 bb [2] ab f5 [2] 96 }

  condition:
    any of them
}