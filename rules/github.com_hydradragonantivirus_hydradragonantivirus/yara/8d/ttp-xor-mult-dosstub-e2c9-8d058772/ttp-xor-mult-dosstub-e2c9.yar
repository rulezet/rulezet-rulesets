rule TTP_XOR_MULT_DOSStub_e2c9 {
  strings:
    $key_e2c9 = { b6 a1 [2] c2 b9 [2] 85 bb [2] c2 aa [2] 8c a6 [2] 80 ac [2] 97 a7 [2] 8c e9 [2] b1 }

  condition:
    any of them
}