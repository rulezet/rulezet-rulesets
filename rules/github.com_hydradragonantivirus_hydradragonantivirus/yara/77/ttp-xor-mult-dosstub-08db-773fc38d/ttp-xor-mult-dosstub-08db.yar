rule TTP_XOR_MULT_DOSStub_08db {
  strings:
    $key_08db = { 5c b3 [2] 28 ab [2] 6f a9 [2] 28 b8 [2] 66 b4 [2] 6a be [2] 7d b5 [2] 66 fb [2] 5b }

  condition:
    any of them
}