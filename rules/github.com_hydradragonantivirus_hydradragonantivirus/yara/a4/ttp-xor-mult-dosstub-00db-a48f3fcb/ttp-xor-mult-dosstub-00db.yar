rule TTP_XOR_MULT_DOSStub_00db {
  strings:
    $key_00db = { 54 b3 [2] 20 ab [2] 67 a9 [2] 20 b8 [2] 6e b4 [2] 62 be [2] 75 b5 [2] 6e fb [2] 53 }

  condition:
    any of them
}