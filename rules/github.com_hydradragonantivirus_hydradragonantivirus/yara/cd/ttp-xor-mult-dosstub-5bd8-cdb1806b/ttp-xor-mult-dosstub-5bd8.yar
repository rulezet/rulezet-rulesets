rule TTP_XOR_MULT_DOSStub_5bd8 {
  strings:
    $key_5bd8 = { 0f b0 [2] 7b a8 [2] 3c aa [2] 7b bb [2] 35 b7 [2] 39 bd [2] 2e b6 [2] 35 f8 [2] 08 }

  condition:
    any of them
}