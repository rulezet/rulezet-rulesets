rule TTP_XOR_MULT_DOSStub_0bdb {
  strings:
    $key_0bdb = { 5f b3 [2] 2b ab [2] 6c a9 [2] 2b b8 [2] 65 b4 [2] 69 be [2] 7e b5 [2] 65 fb [2] 58 }

  condition:
    any of them
}