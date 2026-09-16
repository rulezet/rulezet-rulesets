rule TTP_XOR_MULT_DOSStub_16c9 {
  strings:
    $key_16c9 = { 42 a1 [2] 36 b9 [2] 71 bb [2] 36 aa [2] 78 a6 [2] 74 ac [2] 63 a7 [2] 78 e9 [2] 45 }

  condition:
    any of them
}