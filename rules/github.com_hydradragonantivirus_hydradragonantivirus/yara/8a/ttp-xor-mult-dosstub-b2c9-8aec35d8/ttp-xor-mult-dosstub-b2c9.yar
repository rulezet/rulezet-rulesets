rule TTP_XOR_MULT_DOSStub_b2c9 {
  strings:
    $key_b2c9 = { e6 a1 [2] 92 b9 [2] d5 bb [2] 92 aa [2] dc a6 [2] d0 ac [2] c7 a7 [2] dc e9 [2] e1 }

  condition:
    any of them
}