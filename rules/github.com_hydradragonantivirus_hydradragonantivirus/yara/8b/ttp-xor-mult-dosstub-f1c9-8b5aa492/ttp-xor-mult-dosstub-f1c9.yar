rule TTP_XOR_MULT_DOSStub_f1c9 {
  strings:
    $key_f1c9 = { a5 a1 [2] d1 b9 [2] 96 bb [2] d1 aa [2] 9f a6 [2] 93 ac [2] 84 a7 [2] 9f e9 [2] a2 }

  condition:
    any of them
}