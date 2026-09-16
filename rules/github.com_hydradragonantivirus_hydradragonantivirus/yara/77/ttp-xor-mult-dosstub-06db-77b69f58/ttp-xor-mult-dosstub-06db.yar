rule TTP_XOR_MULT_DOSStub_06db {
  strings:
    $key_06db = { 52 b3 [2] 26 ab [2] 61 a9 [2] 26 b8 [2] 68 b4 [2] 64 be [2] 73 b5 [2] 68 fb [2] 55 }

  condition:
    any of them
}