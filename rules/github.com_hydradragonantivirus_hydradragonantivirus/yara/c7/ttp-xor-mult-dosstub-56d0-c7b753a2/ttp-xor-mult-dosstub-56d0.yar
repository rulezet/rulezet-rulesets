rule TTP_XOR_MULT_DOSStub_56d0 {
  strings:
    $key_56d0 = { 02 b8 [2] 76 a0 [2] 31 a2 [2] 76 b3 [2] 38 bf [2] 34 b5 [2] 23 be [2] 38 f0 [2] 05 }

  condition:
    any of them
}