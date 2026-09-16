rule TTP_XOR_MULT_DOSStub_77d0 {
  strings:
    $key_77d0 = { 23 b8 [2] 57 a0 [2] 10 a2 [2] 57 b3 [2] 19 bf [2] 15 b5 [2] 02 be [2] 19 f0 [2] 24 }

  condition:
    any of them
}