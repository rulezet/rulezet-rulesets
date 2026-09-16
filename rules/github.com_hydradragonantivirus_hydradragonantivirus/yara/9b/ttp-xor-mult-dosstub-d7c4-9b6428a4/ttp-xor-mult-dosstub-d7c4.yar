rule TTP_XOR_MULT_DOSStub_d7c4 {
  strings:
    $key_d7c4 = { 83 ac [2] f7 b4 [2] b0 b6 [2] f7 a7 [2] b9 ab [2] b5 a1 [2] a2 aa [2] b9 e4 [2] 84 }

  condition:
    any of them
}