rule TTP_XOR_MULT_DOSStub_d4c9 {
  strings:
    $key_d4c9 = { 80 a1 [2] f4 b9 [2] b3 bb [2] f4 aa [2] ba a6 [2] b6 ac [2] a1 a7 [2] ba e9 [2] 87 }

  condition:
    any of them
}