rule TTP_XOR_MULT_DOSStub_70db {
  strings:
    $key_70db = { 24 b3 [2] 50 ab [2] 17 a9 [2] 50 b8 [2] 1e b4 [2] 12 be [2] 05 b5 [2] 1e fb [2] 23 }

  condition:
    any of them
}