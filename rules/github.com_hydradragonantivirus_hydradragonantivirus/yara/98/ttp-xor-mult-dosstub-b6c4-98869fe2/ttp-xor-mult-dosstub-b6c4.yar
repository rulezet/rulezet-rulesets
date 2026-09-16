rule TTP_XOR_MULT_DOSStub_b6c4 {
  strings:
    $key_b6c4 = { e2 ac [2] 96 b4 [2] d1 b6 [2] 96 a7 [2] d8 ab [2] d4 a1 [2] c3 aa [2] d8 e4 [2] e5 }

  condition:
    any of them
}