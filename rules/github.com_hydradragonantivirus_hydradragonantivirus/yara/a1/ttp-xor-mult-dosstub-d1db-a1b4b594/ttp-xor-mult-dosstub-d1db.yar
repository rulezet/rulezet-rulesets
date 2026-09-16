rule TTP_XOR_MULT_DOSStub_d1db {
  strings:
    $key_d1db = { 85 b3 [2] f1 ab [2] b6 a9 [2] f1 b8 [2] bf b4 [2] b3 be [2] a4 b5 [2] bf fb [2] 82 }

  condition:
    any of them
}