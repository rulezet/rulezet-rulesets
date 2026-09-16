rule TTP_XOR_MULT_DOSStub_4ec9 {
  strings:
    $key_4ec9 = { 1a a1 [2] 6e b9 [2] 29 bb [2] 6e aa [2] 20 a6 [2] 2c ac [2] 3b a7 [2] 20 e9 [2] 1d }

  condition:
    any of them
}