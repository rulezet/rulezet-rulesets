rule TTP_XOR_MULT_DOSStub_2252 {
  strings:
    $key_2252 = { 76 3a [2] 02 22 [2] 45 20 [2] 02 31 [2] 4c 3d [2] 40 37 [2] 57 3c [2] 4c 72 [2] 71 }

  condition:
    any of them
}