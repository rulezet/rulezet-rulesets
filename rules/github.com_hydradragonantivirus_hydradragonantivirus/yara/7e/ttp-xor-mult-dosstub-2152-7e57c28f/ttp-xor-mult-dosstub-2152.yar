rule TTP_XOR_MULT_DOSStub_2152 {
  strings:
    $key_2152 = { 75 3a [2] 01 22 [2] 46 20 [2] 01 31 [2] 4f 3d [2] 43 37 [2] 54 3c [2] 4f 72 [2] 72 }

  condition:
    any of them
}