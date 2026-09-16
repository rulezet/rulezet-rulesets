rule TTP_XOR_MULT_DOSStub_6452 {
  strings:
    $key_6452 = { 30 3a [2] 44 22 [2] 03 20 [2] 44 31 [2] 0a 3d [2] 06 37 [2] 11 3c [2] 0a 72 [2] 37 }

  condition:
    any of them
}