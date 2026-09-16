rule TTP_XOR_MULT_DOSStub_75db {
  strings:
    $key_75db = { 21 b3 [2] 55 ab [2] 12 a9 [2] 55 b8 [2] 1b b4 [2] 17 be [2] 00 b5 [2] 1b fb [2] 26 }

  condition:
    any of them
}