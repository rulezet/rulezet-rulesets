rule TTP_XOR_MULT_DOSStub_b5c4 {
  strings:
    $key_b5c4 = { e1 ac [2] 95 b4 [2] d2 b6 [2] 95 a7 [2] db ab [2] d7 a1 [2] c0 aa [2] db e4 [2] e6 }

  condition:
    any of them
}