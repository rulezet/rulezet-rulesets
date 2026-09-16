rule TTP_XOR_MULT_DOSStub_c3d8 {
  strings:
    $key_c3d8 = { 97 b0 [2] e3 a8 [2] a4 aa [2] e3 bb [2] ad b7 [2] a1 bd [2] b6 b6 [2] ad f8 [2] 90 }

  condition:
    any of them
}