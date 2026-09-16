rule TTP_XOR_MULT_DOSStub_d5d8 {
  strings:
    $key_d5d8 = { 81 b0 [2] f5 a8 [2] b2 aa [2] f5 bb [2] bb b7 [2] b7 bd [2] a0 b6 [2] bb f8 [2] 86 }

  condition:
    any of them
}