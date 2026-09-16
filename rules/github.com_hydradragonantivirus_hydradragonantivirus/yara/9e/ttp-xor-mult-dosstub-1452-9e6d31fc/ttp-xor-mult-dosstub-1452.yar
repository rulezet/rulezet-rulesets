rule TTP_XOR_MULT_DOSStub_1452 {
  strings:
    $key_1452 = { 40 3a [2] 34 22 [2] 73 20 [2] 34 31 [2] 7a 3d [2] 76 37 [2] 61 3c [2] 7a 72 [2] 47 }

  condition:
    any of them
}