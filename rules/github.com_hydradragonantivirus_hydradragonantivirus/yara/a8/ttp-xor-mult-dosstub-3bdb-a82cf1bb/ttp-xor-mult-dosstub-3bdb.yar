rule TTP_XOR_MULT_DOSStub_3bdb {
  strings:
    $key_3bdb = { 6f b3 [2] 1b ab [2] 5c a9 [2] 1b b8 [2] 55 b4 [2] 59 be [2] 4e b5 [2] 55 fb [2] 68 }

  condition:
    any of them
}