rule TTP_XOR_MULT_DOSStub_d0c9 {
  strings:
    $key_d0c9 = { 84 a1 [2] f0 b9 [2] b7 bb [2] f0 aa [2] be a6 [2] b2 ac [2] a5 a7 [2] be e9 [2] 83 }

  condition:
    any of them
}