rule TTP_XOR_MULT_DOSStub_05c9 {
  strings:
    $key_05c9 = { 51 a1 [2] 25 b9 [2] 62 bb [2] 25 aa [2] 6b a6 [2] 67 ac [2] 70 a7 [2] 6b e9 [2] 56 }

  condition:
    any of them
}