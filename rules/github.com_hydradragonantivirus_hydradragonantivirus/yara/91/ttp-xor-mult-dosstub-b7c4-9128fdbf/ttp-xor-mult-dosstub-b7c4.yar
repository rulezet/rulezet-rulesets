rule TTP_XOR_MULT_DOSStub_b7c4 {
  strings:
    $key_b7c4 = { e3 ac [2] 97 b4 [2] d0 b6 [2] 97 a7 [2] d9 ab [2] d5 a1 [2] c2 aa [2] d9 e4 [2] e4 }

  condition:
    any of them
}