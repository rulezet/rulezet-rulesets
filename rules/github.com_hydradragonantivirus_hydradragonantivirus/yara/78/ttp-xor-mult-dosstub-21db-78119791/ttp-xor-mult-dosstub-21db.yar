rule TTP_XOR_MULT_DOSStub_21db {
  strings:
    $key_21db = { 75 b3 [2] 01 ab [2] 46 a9 [2] 01 b8 [2] 4f b4 [2] 43 be [2] 54 b5 [2] 4f fb [2] 72 }

  condition:
    any of them
}