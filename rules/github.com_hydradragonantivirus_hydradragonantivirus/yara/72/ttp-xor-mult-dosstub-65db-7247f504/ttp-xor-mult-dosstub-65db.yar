rule TTP_XOR_MULT_DOSStub_65db {
  strings:
    $key_65db = { 31 b3 [2] 45 ab [2] 02 a9 [2] 45 b8 [2] 0b b4 [2] 07 be [2] 10 b5 [2] 0b fb [2] 36 }

  condition:
    any of them
}