rule TTP_XOR_MULT_DOSStub_6cd6 {
  strings:
    $key_6cd6 = { 38 be [2] 4c a6 [2] 0b a4 [2] 4c b5 [2] 02 b9 [2] 0e b3 [2] 19 b8 [2] 02 f6 [2] 3f }

  condition:
    any of them
}