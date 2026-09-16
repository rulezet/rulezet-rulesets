rule TTP_XOR_MULT_DOSStub_b5db {
  strings:
    $key_b5db = { e1 b3 [2] 95 ab [2] d2 a9 [2] 95 b8 [2] db b4 [2] d7 be [2] c0 b5 [2] db fb [2] e6 }

  condition:
    any of them
}