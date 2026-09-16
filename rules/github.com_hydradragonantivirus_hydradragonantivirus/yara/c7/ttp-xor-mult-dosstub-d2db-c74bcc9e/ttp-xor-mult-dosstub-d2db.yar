rule TTP_XOR_MULT_DOSStub_d2db {
  strings:
    $key_d2db = { 86 b3 [2] f2 ab [2] b5 a9 [2] f2 b8 [2] bc b4 [2] b0 be [2] a7 b5 [2] bc fb [2] 81 }

  condition:
    any of them
}