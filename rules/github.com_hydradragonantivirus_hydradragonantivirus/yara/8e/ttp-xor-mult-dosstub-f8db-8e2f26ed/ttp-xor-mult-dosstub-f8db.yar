rule TTP_XOR_MULT_DOSStub_f8db {
  strings:
    $key_f8db = { ac b3 [2] d8 ab [2] 9f a9 [2] d8 b8 [2] 96 b4 [2] 9a be [2] 8d b5 [2] 96 fb [2] ab }

  condition:
    any of them
}