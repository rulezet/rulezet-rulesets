rule TTP_XOR_MULT_DOSStub_c1c9 {
  strings:
    $key_c1c9 = { 95 a1 [2] e1 b9 [2] a6 bb [2] e1 aa [2] af a6 [2] a3 ac [2] b4 a7 [2] af e9 [2] 92 }

  condition:
    any of them
}