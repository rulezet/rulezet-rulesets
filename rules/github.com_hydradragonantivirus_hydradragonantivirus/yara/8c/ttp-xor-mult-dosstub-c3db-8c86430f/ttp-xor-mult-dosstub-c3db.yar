rule TTP_XOR_MULT_DOSStub_c3db {
  strings:
    $key_c3db = { 97 b3 [2] e3 ab [2] a4 a9 [2] e3 b8 [2] ad b4 [2] a1 be [2] b6 b5 [2] ad fb [2] 90 }

  condition:
    any of them
}