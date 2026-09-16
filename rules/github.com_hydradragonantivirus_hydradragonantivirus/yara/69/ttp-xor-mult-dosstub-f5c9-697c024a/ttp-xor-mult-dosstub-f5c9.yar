rule TTP_XOR_MULT_DOSStub_f5c9 {
  strings:
    $key_f5c9 = { a1 a1 [2] d5 b9 [2] 92 bb [2] d5 aa [2] 9b a6 [2] 97 ac [2] 80 a7 [2] 9b e9 [2] a6 }

  condition:
    any of them
}