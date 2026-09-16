rule TTP_XOR_MULT_DOSStub_27db {
  strings:
    $key_27db = { 73 b3 [2] 07 ab [2] 40 a9 [2] 07 b8 [2] 49 b4 [2] 45 be [2] 52 b5 [2] 49 fb [2] 74 }

  condition:
    any of them
}