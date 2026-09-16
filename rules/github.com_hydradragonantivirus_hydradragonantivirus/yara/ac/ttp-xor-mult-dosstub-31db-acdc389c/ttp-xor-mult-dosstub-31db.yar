rule TTP_XOR_MULT_DOSStub_31db {
  strings:
    $key_31db = { 65 b3 [2] 11 ab [2] 56 a9 [2] 11 b8 [2] 5f b4 [2] 53 be [2] 44 b5 [2] 5f fb [2] 62 }

  condition:
    any of them
}