rule TTP_XOR_MULT_DOSStub_1055 {
  strings:
    $key_1055 = { 44 3d [2] 30 25 [2] 77 27 [2] 30 36 [2] 7e 3a [2] 72 30 [2] 65 3b [2] 7e 75 [2] 43 }

  condition:
    any of them
}