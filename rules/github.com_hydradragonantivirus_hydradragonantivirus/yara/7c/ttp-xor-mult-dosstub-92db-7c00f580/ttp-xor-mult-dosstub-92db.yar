rule TTP_XOR_MULT_DOSStub_92db {
  strings:
    $key_92db = { c6 b3 [2] b2 ab [2] f5 a9 [2] b2 b8 [2] fc b4 [2] f0 be [2] e7 b5 [2] fc fb [2] c1 }

  condition:
    any of them
}