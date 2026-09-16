rule TTP_XOR_MULT_DOSStub_54db {
  strings:
    $key_54db = { 00 b3 [2] 74 ab [2] 33 a9 [2] 74 b8 [2] 3a b4 [2] 36 be [2] 21 b5 [2] 3a fb [2] 07 }

  condition:
    any of them
}