rule TTP_XOR_MULT_DOSStub_82db {
  strings:
    $key_82db = { d6 b3 [2] a2 ab [2] e5 a9 [2] a2 b8 [2] ec b4 [2] e0 be [2] f7 b5 [2] ec fb [2] d1 }

  condition:
    any of them
}