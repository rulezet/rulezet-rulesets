rule TTP_XOR_MULT_DOSStub_7486 {
  strings:
    $key_7486 = { 20 ee [2] 54 f6 [2] 13 f4 [2] 54 e5 [2] 1a e9 [2] 16 e3 [2] 01 e8 [2] 1a a6 [2] 27 }

  condition:
    any of them
}