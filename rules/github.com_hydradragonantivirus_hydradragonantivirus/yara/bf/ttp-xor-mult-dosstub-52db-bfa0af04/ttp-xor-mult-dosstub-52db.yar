rule TTP_XOR_MULT_DOSStub_52db {
  strings:
    $key_52db = { 06 b3 [2] 72 ab [2] 35 a9 [2] 72 b8 [2] 3c b4 [2] 30 be [2] 27 b5 [2] 3c fb [2] 01 }

  condition:
    any of them
}