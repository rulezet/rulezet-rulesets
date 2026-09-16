rule TTP_XOR_MULT_DOSStub_2ec9 {
  strings:
    $key_2ec9 = { 7a a1 [2] 0e b9 [2] 49 bb [2] 0e aa [2] 40 a6 [2] 4c ac [2] 5b a7 [2] 40 e9 [2] 7d }

  condition:
    any of them
}