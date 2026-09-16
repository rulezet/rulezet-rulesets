rule TTP_XOR_MULT_DOSStub_a1db {
  strings:
    $key_a1db = { f5 b3 [2] 81 ab [2] c6 a9 [2] 81 b8 [2] cf b4 [2] c3 be [2] d4 b5 [2] cf fb [2] f2 }

  condition:
    any of them
}