rule TTP_XOR_MULT_DOSStub_55db {
  strings:
    $key_55db = { 01 b3 [2] 75 ab [2] 32 a9 [2] 75 b8 [2] 3b b4 [2] 37 be [2] 20 b5 [2] 3b fb [2] 06 }

  condition:
    any of them
}