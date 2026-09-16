rule TTP_XOR_MULT_DOSStub_c5db {
  strings:
    $key_c5db = { 91 b3 [2] e5 ab [2] a2 a9 [2] e5 b8 [2] ab b4 [2] a7 be [2] b0 b5 [2] ab fb [2] 96 }

  condition:
    any of them
}