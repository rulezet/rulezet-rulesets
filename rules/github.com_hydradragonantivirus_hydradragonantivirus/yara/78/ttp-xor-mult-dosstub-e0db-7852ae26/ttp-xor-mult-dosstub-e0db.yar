rule TTP_XOR_MULT_DOSStub_e0db {
  strings:
    $key_e0db = { b4 b3 [2] c0 ab [2] 87 a9 [2] c0 b8 [2] 8e b4 [2] 82 be [2] 95 b5 [2] 8e fb [2] b3 }

  condition:
    any of them
}