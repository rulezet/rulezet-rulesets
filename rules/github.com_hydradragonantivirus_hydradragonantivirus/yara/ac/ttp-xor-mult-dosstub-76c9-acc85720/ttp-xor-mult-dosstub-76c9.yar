rule TTP_XOR_MULT_DOSStub_76c9 {
  strings:
    $key_76c9 = { 22 a1 [2] 56 b9 [2] 11 bb [2] 56 aa [2] 18 a6 [2] 14 ac [2] 03 a7 [2] 18 e9 [2] 25 }

  condition:
    any of them
}