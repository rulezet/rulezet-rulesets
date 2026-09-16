rule TTP_XOR_MULT_DOSStub_c1db {
  strings:
    $key_c1db = { 95 b3 [2] e1 ab [2] a6 a9 [2] e1 b8 [2] af b4 [2] a3 be [2] b4 b5 [2] af fb [2] 92 }

  condition:
    any of them
}