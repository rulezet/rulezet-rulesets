rule TTP_XOR_MULT_DOSStub_c6c4 {
  strings:
    $key_c6c4 = { 92 ac [2] e6 b4 [2] a1 b6 [2] e6 a7 [2] a8 ab [2] a4 a1 [2] b3 aa [2] a8 e4 [2] 95 }

  condition:
    any of them
}