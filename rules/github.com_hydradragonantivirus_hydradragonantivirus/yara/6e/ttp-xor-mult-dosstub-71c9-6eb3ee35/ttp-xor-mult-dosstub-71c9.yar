rule TTP_XOR_MULT_DOSStub_71c9 {
  strings:
    $key_71c9 = { 25 a1 [2] 51 b9 [2] 16 bb [2] 51 aa [2] 1f a6 [2] 13 ac [2] 04 a7 [2] 1f e9 [2] 22 }

  condition:
    any of them
}