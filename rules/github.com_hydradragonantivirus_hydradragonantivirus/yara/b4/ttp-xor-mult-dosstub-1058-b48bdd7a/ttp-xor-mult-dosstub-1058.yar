rule TTP_XOR_MULT_DOSStub_1058 {
  strings:
    $key_1058 = { 44 30 [2] 30 28 [2] 77 2a [2] 30 3b [2] 7e 37 [2] 72 3d [2] 65 36 [2] 7e 78 [2] 43 }

  condition:
    any of them
}