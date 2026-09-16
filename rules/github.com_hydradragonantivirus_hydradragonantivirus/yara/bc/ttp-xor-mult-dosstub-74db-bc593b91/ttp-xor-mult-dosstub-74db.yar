rule TTP_XOR_MULT_DOSStub_74db {
  strings:
    $key_74db = { 20 b3 [2] 54 ab [2] 13 a9 [2] 54 b8 [2] 1a b4 [2] 16 be [2] 01 b5 [2] 1a fb [2] 27 }

  condition:
    any of them
}