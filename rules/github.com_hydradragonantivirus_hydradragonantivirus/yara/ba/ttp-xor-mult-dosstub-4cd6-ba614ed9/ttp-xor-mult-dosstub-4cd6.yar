rule TTP_XOR_MULT_DOSStub_4cd6 {
  strings:
    $key_4cd6 = { 18 be [2] 6c a6 [2] 2b a4 [2] 6c b5 [2] 22 b9 [2] 2e b3 [2] 39 b8 [2] 22 f6 [2] 1f }

  condition:
    any of them
}