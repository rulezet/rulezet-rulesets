rule TTP_XOR_MULT_DOSStub_f7c9 {
  strings:
    $key_f7c9 = { a3 a1 [2] d7 b9 [2] 90 bb [2] d7 aa [2] 99 a6 [2] 95 ac [2] 82 a7 [2] 99 e9 [2] a4 }

  condition:
    any of them
}