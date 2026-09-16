rule TTP_XOR_MULT_DOSStub_5252 {
  strings:
    $key_5252 = { 06 3a [2] 72 22 [2] 35 20 [2] 72 31 [2] 3c 3d [2] 30 37 [2] 27 3c [2] 3c 72 [2] 01 }

  condition:
    any of them
}