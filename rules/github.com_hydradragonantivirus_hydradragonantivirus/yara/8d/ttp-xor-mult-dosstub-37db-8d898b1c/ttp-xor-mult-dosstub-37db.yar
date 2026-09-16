rule TTP_XOR_MULT_DOSStub_37db {
  strings:
    $key_37db = { 63 b3 [2] 17 ab [2] 50 a9 [2] 17 b8 [2] 59 b4 [2] 55 be [2] 42 b5 [2] 59 fb [2] 64 }

  condition:
    any of them
}