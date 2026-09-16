rule TTP_XOR_MULT_DOSStub_86db {
  strings:
    $key_86db = { d2 b3 [2] a6 ab [2] e1 a9 [2] a6 b8 [2] e8 b4 [2] e4 be [2] f3 b5 [2] e8 fb [2] d5 }

  condition:
    any of them
}