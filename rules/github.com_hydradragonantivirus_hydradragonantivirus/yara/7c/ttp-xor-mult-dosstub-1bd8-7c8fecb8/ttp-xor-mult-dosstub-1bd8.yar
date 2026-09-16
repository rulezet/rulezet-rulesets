rule TTP_XOR_MULT_DOSStub_1bd8 {
  strings:
    $key_1bd8 = { 4f b0 [2] 3b a8 [2] 7c aa [2] 3b bb [2] 75 b7 [2] 79 bd [2] 6e b6 [2] 75 f8 [2] 48 }

  condition:
    any of them
}