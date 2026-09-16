rule TTP_XOR_MULT_DOSStub_4bdb {
  strings:
    $key_4bdb = { 1f b3 [2] 6b ab [2] 2c a9 [2] 6b b8 [2] 25 b4 [2] 29 be [2] 3e b5 [2] 25 fb [2] 18 }

  condition:
    any of them
}