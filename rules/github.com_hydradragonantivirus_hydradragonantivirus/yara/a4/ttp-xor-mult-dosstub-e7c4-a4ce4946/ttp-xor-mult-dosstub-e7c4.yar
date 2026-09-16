rule TTP_XOR_MULT_DOSStub_e7c4 {
  strings:
    $key_e7c4 = { b3 ac [2] c7 b4 [2] 80 b6 [2] c7 a7 [2] 89 ab [2] 85 a1 [2] 92 aa [2] 89 e4 [2] b4 }

  condition:
    any of them
}