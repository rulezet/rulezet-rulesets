rule TTP_XOR_MULT_DOSStub_d2d8 {
  strings:
    $key_d2d8 = { 86 b0 [2] f2 a8 [2] b5 aa [2] f2 bb [2] bc b7 [2] b0 bd [2] a7 b6 [2] bc f8 [2] 81 }

  condition:
    any of them
}