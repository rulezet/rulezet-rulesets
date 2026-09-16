rule TTP_XOR_MULT_DOSStub_d6c9 {
  strings:
    $key_d6c9 = { 82 a1 [2] f6 b9 [2] b1 bb [2] f6 aa [2] b8 a6 [2] b4 ac [2] a3 a7 [2] b8 e9 [2] 85 }

  condition:
    any of them
}