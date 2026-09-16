rule TTP_XOR_MULT_DOSStub_63db {
  strings:
    $key_63db = { 37 b3 [2] 43 ab [2] 04 a9 [2] 43 b8 [2] 0d b4 [2] 01 be [2] 16 b5 [2] 0d fb [2] 30 }

  condition:
    any of them
}