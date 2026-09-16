rule TTP_XOR_MULT_DOSStub_94db {
  strings:
    $key_94db = { c0 b3 [2] b4 ab [2] f3 a9 [2] b4 b8 [2] fa b4 [2] f6 be [2] e1 b5 [2] fa fb [2] c7 }

  condition:
    any of them
}