rule TTP_XOR_MULT_DOSStub_f6c9 {
  strings:
    $key_f6c9 = { a2 a1 [2] d6 b9 [2] 91 bb [2] d6 aa [2] 98 a6 [2] 94 ac [2] 83 a7 [2] 98 e9 [2] a5 }

  condition:
    any of them
}