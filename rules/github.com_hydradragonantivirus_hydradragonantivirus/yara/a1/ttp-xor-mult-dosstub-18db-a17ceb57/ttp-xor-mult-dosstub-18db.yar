rule TTP_XOR_MULT_DOSStub_18db {
  strings:
    $key_18db = { 4c b3 [2] 38 ab [2] 7f a9 [2] 38 b8 [2] 76 b4 [2] 7a be [2] 6d b5 [2] 76 fb [2] 4b }

  condition:
    any of them
}