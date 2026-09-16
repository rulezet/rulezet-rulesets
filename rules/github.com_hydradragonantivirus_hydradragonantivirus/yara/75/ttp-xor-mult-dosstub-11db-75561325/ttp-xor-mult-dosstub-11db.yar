rule TTP_XOR_MULT_DOSStub_11db {
  strings:
    $key_11db = { 45 b3 [2] 31 ab [2] 76 a9 [2] 31 b8 [2] 7f b4 [2] 73 be [2] 64 b5 [2] 7f fb [2] 42 }

  condition:
    any of them
}