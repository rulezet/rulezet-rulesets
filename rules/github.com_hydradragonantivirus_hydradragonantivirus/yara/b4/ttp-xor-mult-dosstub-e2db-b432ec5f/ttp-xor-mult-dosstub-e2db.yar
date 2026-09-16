rule TTP_XOR_MULT_DOSStub_e2db {
  strings:
    $key_e2db = { b6 b3 [2] c2 ab [2] 85 a9 [2] c2 b8 [2] 8c b4 [2] 80 be [2] 97 b5 [2] 8c fb [2] b1 }

  condition:
    any of them
}