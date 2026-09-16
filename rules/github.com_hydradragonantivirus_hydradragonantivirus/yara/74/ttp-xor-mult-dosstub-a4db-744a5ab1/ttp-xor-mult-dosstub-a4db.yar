rule TTP_XOR_MULT_DOSStub_a4db {
  strings:
    $key_a4db = { f0 b3 [2] 84 ab [2] c3 a9 [2] 84 b8 [2] ca b4 [2] c6 be [2] d1 b5 [2] ca fb [2] f7 }

  condition:
    any of them
}