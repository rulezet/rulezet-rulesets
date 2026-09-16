rule TTP_XOR_MULT_DOSStub_50db {
  strings:
    $key_50db = { 04 b3 [2] 70 ab [2] 37 a9 [2] 70 b8 [2] 3e b4 [2] 32 be [2] 25 b5 [2] 3e fb [2] 03 }

  condition:
    any of them
}