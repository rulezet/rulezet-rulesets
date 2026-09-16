rule TTP_XOR_MULT_DOSStub_81d8 {
  strings:
    $key_81d8 = { d5 b0 [2] a1 a8 [2] e6 aa [2] a1 bb [2] ef b7 [2] e3 bd [2] f4 b6 [2] ef f8 [2] d2 }

  condition:
    any of them
}