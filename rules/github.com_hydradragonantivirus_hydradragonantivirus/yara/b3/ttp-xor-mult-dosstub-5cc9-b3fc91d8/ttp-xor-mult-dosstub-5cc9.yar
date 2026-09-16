rule TTP_XOR_MULT_DOSStub_5cc9 {
  strings:
    $key_5cc9 = { 08 a1 [2] 7c b9 [2] 3b bb [2] 7c aa [2] 32 a6 [2] 3e ac [2] 29 a7 [2] 32 e9 [2] 0f }

  condition:
    any of them
}