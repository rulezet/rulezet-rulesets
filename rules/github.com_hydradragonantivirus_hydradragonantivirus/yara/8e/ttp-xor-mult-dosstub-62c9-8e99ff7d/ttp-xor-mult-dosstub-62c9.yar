rule TTP_XOR_MULT_DOSStub_62c9 {
  strings:
    $key_62c9 = { 36 a1 [2] 42 b9 [2] 05 bb [2] 42 aa [2] 0c a6 [2] 00 ac [2] 17 a7 [2] 0c e9 [2] 31 }

  condition:
    any of them
}