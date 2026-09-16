rule TTP_XOR_MULT_DOSStub_c2d8 {
  strings:
    $key_c2d8 = { 96 b0 [2] e2 a8 [2] a5 aa [2] e2 bb [2] ac b7 [2] a0 bd [2] b7 b6 [2] ac f8 [2] 91 }

  condition:
    any of them
}