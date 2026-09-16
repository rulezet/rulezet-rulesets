rule TTP_XOR_MULT_DOSStub_b7c9 {
  strings:
    $key_b7c9 = { e3 a1 [2] 97 b9 [2] d0 bb [2] 97 aa [2] d9 a6 [2] d5 ac [2] c2 a7 [2] d9 e9 [2] e4 }

  condition:
    any of them
}