rule TTP_XOR_MULT_DOSStub_01c9 {
  strings:
    $key_01c9 = { 55 a1 [2] 21 b9 [2] 66 bb [2] 21 aa [2] 6f a6 [2] 63 ac [2] 74 a7 [2] 6f e9 [2] 52 }

  condition:
    any of them
}