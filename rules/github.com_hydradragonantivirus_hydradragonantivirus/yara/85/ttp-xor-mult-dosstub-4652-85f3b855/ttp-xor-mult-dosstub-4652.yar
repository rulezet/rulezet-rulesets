rule TTP_XOR_MULT_DOSStub_4652 {
  strings:
    $key_4652 = { 12 3a [2] 66 22 [2] 21 20 [2] 66 31 [2] 28 3d [2] 24 37 [2] 33 3c [2] 28 72 [2] 15 }

  condition:
    any of them
}