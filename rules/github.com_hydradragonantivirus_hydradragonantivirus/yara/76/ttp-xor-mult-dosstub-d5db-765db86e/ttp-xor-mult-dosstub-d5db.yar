rule TTP_XOR_MULT_DOSStub_d5db {
  strings:
    $key_d5db = { 81 b3 [2] f5 ab [2] b2 a9 [2] f5 b8 [2] bb b4 [2] b7 be [2] a0 b5 [2] bb fb [2] 86 }

  condition:
    any of them
}