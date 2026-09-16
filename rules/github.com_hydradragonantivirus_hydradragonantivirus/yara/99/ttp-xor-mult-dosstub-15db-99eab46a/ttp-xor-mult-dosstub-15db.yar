rule TTP_XOR_MULT_DOSStub_15db {
  strings:
    $key_15db = { 41 b3 [2] 35 ab [2] 72 a9 [2] 35 b8 [2] 7b b4 [2] 77 be [2] 60 b5 [2] 7b fb [2] 46 }

  condition:
    any of them
}