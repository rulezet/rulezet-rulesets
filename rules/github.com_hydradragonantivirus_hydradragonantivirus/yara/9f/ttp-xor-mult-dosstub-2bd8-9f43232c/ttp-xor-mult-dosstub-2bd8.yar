rule TTP_XOR_MULT_DOSStub_2bd8 {
  strings:
    $key_2bd8 = { 7f b0 [2] 0b a8 [2] 4c aa [2] 0b bb [2] 45 b7 [2] 49 bd [2] 5e b6 [2] 45 f8 [2] 78 }

  condition:
    any of them
}