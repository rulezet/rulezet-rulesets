rule TTP_XOR_MULT_DOSStub_36db {
  strings:
    $key_36db = { 62 b3 [2] 16 ab [2] 51 a9 [2] 16 b8 [2] 58 b4 [2] 54 be [2] 43 b5 [2] 58 fb [2] 65 }

  condition:
    any of them
}