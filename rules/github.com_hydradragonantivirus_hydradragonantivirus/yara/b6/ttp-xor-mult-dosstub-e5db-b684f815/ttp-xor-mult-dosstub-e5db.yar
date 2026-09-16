rule TTP_XOR_MULT_DOSStub_e5db {
  strings:
    $key_e5db = { b1 b3 [2] c5 ab [2] 82 a9 [2] c5 b8 [2] 8b b4 [2] 87 be [2] 90 b5 [2] 8b fb [2] b6 }

  condition:
    any of them
}