rule TTP_XOR_MULT_DOSStub_22c9 {
  strings:
    $key_22c9 = { 76 a1 [2] 02 b9 [2] 45 bb [2] 02 aa [2] 4c a6 [2] 40 ac [2] 57 a7 [2] 4c e9 [2] 71 }

  condition:
    any of them
}