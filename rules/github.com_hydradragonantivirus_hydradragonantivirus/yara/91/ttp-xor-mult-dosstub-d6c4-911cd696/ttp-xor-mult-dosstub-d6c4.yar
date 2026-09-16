rule TTP_XOR_MULT_DOSStub_d6c4 {
  strings:
    $key_d6c4 = { 82 ac [2] f6 b4 [2] b1 b6 [2] f6 a7 [2] b8 ab [2] b4 a1 [2] a3 aa [2] b8 e4 [2] 85 }

  condition:
    any of them
}