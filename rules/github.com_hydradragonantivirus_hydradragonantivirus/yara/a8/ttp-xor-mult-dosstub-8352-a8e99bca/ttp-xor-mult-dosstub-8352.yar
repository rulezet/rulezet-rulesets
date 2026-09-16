rule TTP_XOR_MULT_DOSStub_8352 {
  strings:
    $key_8352 = { d7 3a [2] a3 22 [2] e4 20 [2] a3 31 [2] ed 3d [2] e1 37 [2] f6 3c [2] ed 72 [2] d0 }

  condition:
    any of them
}