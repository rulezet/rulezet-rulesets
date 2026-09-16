rule TTP_XOR_MULT_DOSStub_07db {
  strings:
    $key_07db = { 53 b3 [2] 27 ab [2] 60 a9 [2] 27 b8 [2] 69 b4 [2] 65 be [2] 72 b5 [2] 69 fb [2] 54 }

  condition:
    any of them
}