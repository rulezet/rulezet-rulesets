rule TTP_XOR_MULT_DOSStub_d7d8 {
  strings:
    $key_d7d8 = { 83 b0 [2] f7 a8 [2] b0 aa [2] f7 bb [2] b9 b7 [2] b5 bd [2] a2 b6 [2] b9 f8 [2] 84 }

  condition:
    any of them
}