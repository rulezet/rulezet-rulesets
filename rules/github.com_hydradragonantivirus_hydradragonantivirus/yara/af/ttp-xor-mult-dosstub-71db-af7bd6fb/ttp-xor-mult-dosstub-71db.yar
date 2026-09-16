rule TTP_XOR_MULT_DOSStub_71db {
  strings:
    $key_71db = { 25 b3 [2] 51 ab [2] 16 a9 [2] 51 b8 [2] 1f b4 [2] 13 be [2] 04 b5 [2] 1f fb [2] 22 }

  condition:
    any of them
}