rule TTP_XOR_MULT_DOSStub_38db {
  strings:
    $key_38db = { 6c b3 [2] 18 ab [2] 5f a9 [2] 18 b8 [2] 56 b4 [2] 5a be [2] 4d b5 [2] 56 fb [2] 6b }

  condition:
    any of them
}