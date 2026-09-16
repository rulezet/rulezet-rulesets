rule TTP_XOR_MULT_DOSStub_16db {
  strings:
    $key_16db = { 42 b3 [2] 36 ab [2] 71 a9 [2] 36 b8 [2] 78 b4 [2] 74 be [2] 63 b5 [2] 78 fb [2] 45 }

  condition:
    any of them
}