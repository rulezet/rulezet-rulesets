rule TTP_XOR_MULT_DOSStub_d6db {
  strings:
    $key_d6db = { 82 b3 [2] f6 ab [2] b1 a9 [2] f6 b8 [2] b8 b4 [2] b4 be [2] a3 b5 [2] b8 fb [2] 85 }

  condition:
    any of them
}