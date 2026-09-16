rule TTP_XOR_MULT_DOSStub_f1db {
  strings:
    $key_f1db = { a5 b3 [2] d1 ab [2] 96 a9 [2] d1 b8 [2] 9f b4 [2] 93 be [2] 84 b5 [2] 9f fb [2] a2 }

  condition:
    any of them
}