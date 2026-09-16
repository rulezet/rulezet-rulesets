rule TTP_XOR_MULT_DOSStub_7452 {
  strings:
    $key_7452 = { 20 3a [2] 54 22 [2] 13 20 [2] 54 31 [2] 1a 3d [2] 16 37 [2] 01 3c [2] 1a 72 [2] 27 }

  condition:
    any of them
}