rule TTP_XOR_MULT_DOSStub_d7db {
  strings:
    $key_d7db = { 83 b3 [2] f7 ab [2] b0 a9 [2] f7 b8 [2] b9 b4 [2] b5 be [2] a2 b5 [2] b9 fb [2] 84 }

  condition:
    any of them
}