rule TTP_XOR_MULT_DOSStub_f4c9 {
  strings:
    $key_f4c9 = { a0 a1 [2] d4 b9 [2] 93 bb [2] d4 aa [2] 9a a6 [2] 96 ac [2] 81 a7 [2] 9a e9 [2] a7 }

  condition:
    any of them
}