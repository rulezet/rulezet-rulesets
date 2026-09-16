rule TTP_XOR_MULT_DOSStub_d7c9 {
  strings:
    $key_d7c9 = { 83 a1 [2] f7 b9 [2] b0 bb [2] f7 aa [2] b9 a6 [2] b5 ac [2] a2 a7 [2] b9 e9 [2] 84 }

  condition:
    any of them
}