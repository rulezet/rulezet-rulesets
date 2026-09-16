rule TTP_XOR_MULT_DOSStub_d0db {
  strings:
    $key_d0db = { 84 b3 [2] f0 ab [2] b7 a9 [2] f0 b8 [2] be b4 [2] b2 be [2] a5 b5 [2] be fb [2] 83 }

  condition:
    any of them
}