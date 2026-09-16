rule TTP_XOR_MULT_DOSStub_1052 {
  strings:
    $key_1052 = { 44 3a [2] 30 22 [2] 77 20 [2] 30 31 [2] 7e 3d [2] 72 37 [2] 65 3c [2] 7e 72 [2] 43 }

  condition:
    any of them
}