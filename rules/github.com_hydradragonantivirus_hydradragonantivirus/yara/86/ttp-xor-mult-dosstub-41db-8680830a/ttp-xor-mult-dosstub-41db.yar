rule TTP_XOR_MULT_DOSStub_41db {
  strings:
    $key_41db = { 15 b3 [2] 61 ab [2] 26 a9 [2] 61 b8 [2] 2f b4 [2] 23 be [2] 34 b5 [2] 2f fb [2] 12 }

  condition:
    any of them
}