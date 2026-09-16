rule TTP_XOR_MULT_DOSStub_b6db {
  strings:
    $key_b6db = { e2 b3 [2] 96 ab [2] d1 a9 [2] 96 b8 [2] d8 b4 [2] d4 be [2] c3 b5 [2] d8 fb [2] e5 }

  condition:
    any of them
}