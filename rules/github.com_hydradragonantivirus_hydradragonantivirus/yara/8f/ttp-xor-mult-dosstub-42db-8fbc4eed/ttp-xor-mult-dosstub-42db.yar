rule TTP_XOR_MULT_DOSStub_42db {
  strings:
    $key_42db = { 16 b3 [2] 62 ab [2] 25 a9 [2] 62 b8 [2] 2c b4 [2] 20 be [2] 37 b5 [2] 2c fb [2] 11 }

  condition:
    any of them
}