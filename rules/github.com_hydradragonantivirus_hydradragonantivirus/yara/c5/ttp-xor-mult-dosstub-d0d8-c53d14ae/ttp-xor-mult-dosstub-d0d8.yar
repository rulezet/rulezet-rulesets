rule TTP_XOR_MULT_DOSStub_d0d8 {
  strings:
    $key_d0d8 = { 84 b0 [2] f0 a8 [2] b7 aa [2] f0 bb [2] be b7 [2] b2 bd [2] a5 b6 [2] be f8 [2] 83 }

  condition:
    any of them
}