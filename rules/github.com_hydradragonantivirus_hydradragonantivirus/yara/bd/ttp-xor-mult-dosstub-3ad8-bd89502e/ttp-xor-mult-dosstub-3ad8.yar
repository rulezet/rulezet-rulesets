rule TTP_XOR_MULT_DOSStub_3ad8 {
  strings:
    $key_3ad8 = { 6e b0 [2] 1a a8 [2] 5d aa [2] 1a bb [2] 54 b7 [2] 58 bd [2] 4f b6 [2] 54 f8 [2] 69 }

  condition:
    any of them
}