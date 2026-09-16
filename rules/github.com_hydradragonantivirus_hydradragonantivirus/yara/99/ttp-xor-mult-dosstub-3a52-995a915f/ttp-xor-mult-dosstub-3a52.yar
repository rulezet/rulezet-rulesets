rule TTP_XOR_MULT_DOSStub_3a52 {
  strings:
    $key_3a52 = { 6e 3a [2] 1a 22 [2] 5d 20 [2] 1a 31 [2] 54 3d [2] 58 37 [2] 4f 3c [2] 54 72 [2] 69 }

  condition:
    any of them
}