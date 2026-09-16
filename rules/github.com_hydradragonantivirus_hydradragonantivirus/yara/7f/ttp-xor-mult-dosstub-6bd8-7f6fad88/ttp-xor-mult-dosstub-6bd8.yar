rule TTP_XOR_MULT_DOSStub_6bd8 {
  strings:
    $key_6bd8 = { 3f b0 [2] 4b a8 [2] 0c aa [2] 4b bb [2] 05 b7 [2] 09 bd [2] 1e b6 [2] 05 f8 [2] 38 }

  condition:
    any of them
}