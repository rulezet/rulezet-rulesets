rule TTP_XOR_MULT_DOSStub_b0c9 {
  strings:
    $key_b0c9 = { e4 a1 [2] 90 b9 [2] d7 bb [2] 90 aa [2] de a6 [2] d2 ac [2] c5 a7 [2] de e9 [2] e3 }

  condition:
    any of them
}