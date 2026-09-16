rule TTP_XOR_MULT_DOSStub_d6d8 {
  strings:
    $key_d6d8 = { 82 b0 [2] f6 a8 [2] b1 aa [2] f6 bb [2] b8 b7 [2] b4 bd [2] a3 b6 [2] b8 f8 [2] 85 }

  condition:
    any of them
}