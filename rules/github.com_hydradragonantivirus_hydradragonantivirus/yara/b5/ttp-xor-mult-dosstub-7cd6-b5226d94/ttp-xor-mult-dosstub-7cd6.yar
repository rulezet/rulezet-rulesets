rule TTP_XOR_MULT_DOSStub_7cd6 {
  strings:
    $key_7cd6 = { 28 be [2] 5c a6 [2] 1b a4 [2] 5c b5 [2] 12 b9 [2] 1e b3 [2] 09 b8 [2] 12 f6 [2] 2f }

  condition:
    any of them
}