rule TTP_XOR_MULT_DOSStub_56db {
  strings:
    $key_56db = { 02 b3 [2] 76 ab [2] 31 a9 [2] 76 b8 [2] 38 b4 [2] 34 be [2] 23 b5 [2] 38 fb [2] 05 }

  condition:
    any of them
}