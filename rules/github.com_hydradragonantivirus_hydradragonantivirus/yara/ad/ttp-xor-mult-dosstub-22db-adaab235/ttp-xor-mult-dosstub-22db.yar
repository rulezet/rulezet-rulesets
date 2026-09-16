rule TTP_XOR_MULT_DOSStub_22db {
  strings:
    $key_22db = { 76 b3 [2] 02 ab [2] 45 a9 [2] 02 b8 [2] 4c b4 [2] 40 be [2] 57 b5 [2] 4c fb [2] 71 }

  condition:
    any of them
}