rule TTP_XOR_MULT_DOSStub_60db {
  strings:
    $key_60db = { 34 b3 [2] 40 ab [2] 07 a9 [2] 40 b8 [2] 0e b4 [2] 02 be [2] 15 b5 [2] 0e fb [2] 33 }

  condition:
    any of them
}