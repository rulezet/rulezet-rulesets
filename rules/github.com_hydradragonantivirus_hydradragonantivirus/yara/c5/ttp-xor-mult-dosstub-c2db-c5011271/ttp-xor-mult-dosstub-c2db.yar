rule TTP_XOR_MULT_DOSStub_c2db {
  strings:
    $key_c2db = { 96 b3 [2] e2 ab [2] a5 a9 [2] e2 b8 [2] ac b4 [2] a0 be [2] b7 b5 [2] ac fb [2] 91 }

  condition:
    any of them
}