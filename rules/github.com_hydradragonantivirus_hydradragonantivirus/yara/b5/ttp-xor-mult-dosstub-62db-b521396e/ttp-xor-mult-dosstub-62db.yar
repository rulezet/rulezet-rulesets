rule TTP_XOR_MULT_DOSStub_62db {
  strings:
    $key_62db = { 36 b3 [2] 42 ab [2] 05 a9 [2] 42 b8 [2] 0c b4 [2] 00 be [2] 17 b5 [2] 0c fb [2] 31 }

  condition:
    any of them
}