rule TTP_XOR_MULT_DOSStub_0ec9 {
  strings:
    $key_0ec9 = { 5a a1 [2] 2e b9 [2] 69 bb [2] 2e aa [2] 60 a6 [2] 6c ac [2] 7b a7 [2] 60 e9 [2] 5d }

  condition:
    any of them
}