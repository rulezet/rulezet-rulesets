rule TTP_XOR_MULT_DOSStub_72db {
  strings:
    $key_72db = { 26 b3 [2] 52 ab [2] 15 a9 [2] 52 b8 [2] 1c b4 [2] 10 be [2] 07 b5 [2] 1c fb [2] 21 }

  condition:
    any of them
}