rule TTP_XOR_MULT_DOSStub_7bd8 {
  strings:
    $key_7bd8 = { 2f b0 [2] 5b a8 [2] 1c aa [2] 5b bb [2] 15 b7 [2] 19 bd [2] 0e b6 [2] 15 f8 [2] 28 }

  condition:
    any of them
}