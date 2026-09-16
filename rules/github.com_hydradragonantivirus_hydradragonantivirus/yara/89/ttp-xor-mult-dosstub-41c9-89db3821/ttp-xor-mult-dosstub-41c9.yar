rule TTP_XOR_MULT_DOSStub_41c9 {
  strings:
    $key_41c9 = { 15 a1 [2] 61 b9 [2] 26 bb [2] 61 aa [2] 2f a6 [2] 23 ac [2] 34 a7 [2] 2f e9 [2] 12 }

  condition:
    any of them
}