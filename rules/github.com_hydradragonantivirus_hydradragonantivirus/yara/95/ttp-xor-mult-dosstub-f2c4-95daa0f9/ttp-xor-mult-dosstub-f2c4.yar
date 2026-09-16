rule TTP_XOR_MULT_DOSStub_f2c4 {
  strings:
    $key_f2c4 = { a6 ac [2] d2 b4 [2] 95 b6 [2] d2 a7 [2] 9c ab [2] 90 a1 [2] 87 aa [2] 9c e4 [2] a1 }

  condition:
    any of them
}