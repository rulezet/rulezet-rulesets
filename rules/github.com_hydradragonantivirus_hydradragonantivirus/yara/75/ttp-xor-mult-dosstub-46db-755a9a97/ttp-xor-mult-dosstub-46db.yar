rule TTP_XOR_MULT_DOSStub_46db {
  strings:
    $key_46db = { 12 b3 [2] 66 ab [2] 21 a9 [2] 66 b8 [2] 28 b4 [2] 24 be [2] 33 b5 [2] 28 fb [2] 15 }

  condition:
    any of them
}