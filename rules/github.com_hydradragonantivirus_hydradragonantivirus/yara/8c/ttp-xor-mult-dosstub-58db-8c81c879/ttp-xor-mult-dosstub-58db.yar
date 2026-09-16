rule TTP_XOR_MULT_DOSStub_58db {
  strings:
    $key_58db = { 0c b3 [2] 78 ab [2] 3f a9 [2] 78 b8 [2] 36 b4 [2] 3a be [2] 2d b5 [2] 36 fb [2] 0b }

  condition:
    any of them
}