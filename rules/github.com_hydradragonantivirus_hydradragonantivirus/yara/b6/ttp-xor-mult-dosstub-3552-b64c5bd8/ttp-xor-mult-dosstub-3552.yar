rule TTP_XOR_MULT_DOSStub_3552 {
  strings:
    $key_3552 = { 61 3a [2] 15 22 [2] 52 20 [2] 15 31 [2] 5b 3d [2] 57 37 [2] 40 3c [2] 5b 72 [2] 66 }

  condition:
    any of them
}