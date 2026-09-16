rule TTP_XOR_MULT_DOSStub_51c9 {
  strings:
    $key_51c9 = { 05 a1 [2] 71 b9 [2] 36 bb [2] 71 aa [2] 3f a6 [2] 33 ac [2] 24 a7 [2] 3f e9 [2] 02 }

  condition:
    any of them
}