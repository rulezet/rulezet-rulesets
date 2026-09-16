rule TTP_XOR_MULT_DOSStub_d4d8 {
  strings:
    $key_d4d8 = { 80 b0 [2] f4 a8 [2] b3 aa [2] f4 bb [2] ba b7 [2] b6 bd [2] a1 b6 [2] ba f8 [2] 87 }

  condition:
    any of them
}