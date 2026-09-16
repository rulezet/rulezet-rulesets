rule TTP_XOR_MULT_DOSStub_a6db {
  strings:
    $key_a6db = { f2 b3 [2] 86 ab [2] c1 a9 [2] 86 b8 [2] c8 b4 [2] c4 be [2] d3 b5 [2] c8 fb [2] f5 }

  condition:
    any of them
}