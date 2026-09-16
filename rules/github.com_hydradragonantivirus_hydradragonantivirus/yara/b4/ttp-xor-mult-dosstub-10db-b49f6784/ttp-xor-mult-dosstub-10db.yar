rule TTP_XOR_MULT_DOSStub_10db {
  strings:
    $key_10db = { 44 b3 [2] 30 ab [2] 77 a9 [2] 30 b8 [2] 7e b4 [2] 72 be [2] 65 b5 [2] 7e fb [2] 43 }

  condition:
    any of them
}