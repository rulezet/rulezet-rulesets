rule TTP_XOR_MULT_DOSStub_24db {
  strings:
    $key_24db = { 70 b3 [2] 04 ab [2] 43 a9 [2] 04 b8 [2] 4a b4 [2] 46 be [2] 51 b5 [2] 4a fb [2] 77 }

  condition:
    any of them
}