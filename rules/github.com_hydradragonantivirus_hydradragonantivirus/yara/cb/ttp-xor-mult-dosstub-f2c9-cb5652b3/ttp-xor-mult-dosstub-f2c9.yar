rule TTP_XOR_MULT_DOSStub_f2c9 {
  strings:
    $key_f2c9 = { a6 a1 [2] d2 b9 [2] 95 bb [2] d2 aa [2] 9c a6 [2] 90 ac [2] 87 a7 [2] 9c e9 [2] a1 }

  condition:
    any of them
}