rule TTP_XOR_MULT_DOSStub_4bd8 {
  strings:
    $key_4bd8 = { 1f b0 [2] 6b a8 [2] 2c aa [2] 6b bb [2] 25 b7 [2] 29 bd [2] 3e b6 [2] 25 f8 [2] 18 }

  condition:
    any of them
}