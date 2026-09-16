rule TTP_XOR_MULT_DOSStub_b0c4 {
  strings:
    $key_b0c4 = { e4 ac [2] 90 b4 [2] d7 b6 [2] 90 a7 [2] de ab [2] d2 a1 [2] c5 aa [2] de e4 [2] e3 }

  condition:
    any of them
}