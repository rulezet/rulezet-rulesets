rule TTP_XOR_MULT_DOSStub_45db {
  strings:
    $key_45db = { 11 b3 [2] 65 ab [2] 22 a9 [2] 65 b8 [2] 2b b4 [2] 27 be [2] 30 b5 [2] 2b fb [2] 16 }

  condition:
    any of them
}