rule TTP_XOR_MULT_DOSStub_e8db {
  strings:
    $key_e8db = { bc b3 [2] c8 ab [2] 8f a9 [2] c8 b8 [2] 86 b4 [2] 8a be [2] 9d b5 [2] 86 fb [2] bb }

  condition:
    any of them
}