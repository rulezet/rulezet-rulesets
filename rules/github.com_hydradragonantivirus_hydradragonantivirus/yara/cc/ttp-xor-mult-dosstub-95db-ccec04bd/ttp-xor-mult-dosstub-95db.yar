rule TTP_XOR_MULT_DOSStub_95db {
  strings:
    $key_95db = { c1 b3 [2] b5 ab [2] f2 a9 [2] b5 b8 [2] fb b4 [2] f7 be [2] e0 b5 [2] fb fb [2] c6 }

  condition:
    any of them
}