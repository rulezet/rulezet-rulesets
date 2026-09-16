rule TTP_XOR_MULT_DOSStub_13c9 {
  strings:
    $key_13c9 = { 47 a1 [2] 33 b9 [2] 74 bb [2] 33 aa [2] 7d a6 [2] 71 ac [2] 66 a7 [2] 7d e9 [2] 40 }

  condition:
    any of them
}