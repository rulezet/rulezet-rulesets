rule TTP_XOR_MULT_DOSStub_11c9 {
  strings:
    $key_11c9 = { 45 a1 [2] 31 b9 [2] 76 bb [2] 31 aa [2] 7f a6 [2] 73 ac [2] 64 a7 [2] 7f e9 [2] 42 }

  condition:
    any of them
}