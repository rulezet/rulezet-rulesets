rule TTP_XOR_MULT_DOSStub_7cc9 {
  strings:
    $key_7cc9 = { 28 a1 [2] 5c b9 [2] 1b bb [2] 5c aa [2] 12 a6 [2] 1e ac [2] 09 a7 [2] 12 e9 [2] 2f }

  condition:
    any of them
}