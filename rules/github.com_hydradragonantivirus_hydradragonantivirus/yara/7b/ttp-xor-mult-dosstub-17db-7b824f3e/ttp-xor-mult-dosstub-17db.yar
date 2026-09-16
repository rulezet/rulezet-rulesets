rule TTP_XOR_MULT_DOSStub_17db {
  strings:
    $key_17db = { 43 b3 [2] 37 ab [2] 70 a9 [2] 37 b8 [2] 79 b4 [2] 75 be [2] 62 b5 [2] 79 fb [2] 44 }

  condition:
    any of them
}