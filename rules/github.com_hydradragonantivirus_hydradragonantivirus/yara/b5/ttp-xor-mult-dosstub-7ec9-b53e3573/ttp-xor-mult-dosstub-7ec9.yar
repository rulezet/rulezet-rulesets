rule TTP_XOR_MULT_DOSStub_7ec9 {
  strings:
    $key_7ec9 = { 2a a1 [2] 5e b9 [2] 19 bb [2] 5e aa [2] 10 a6 [2] 1c ac [2] 0b a7 [2] 10 e9 [2] 2d }

  condition:
    any of them
}