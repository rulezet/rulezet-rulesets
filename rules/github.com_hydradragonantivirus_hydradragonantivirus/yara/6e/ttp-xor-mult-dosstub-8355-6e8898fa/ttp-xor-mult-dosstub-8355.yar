rule TTP_XOR_MULT_DOSStub_8355 {
  strings:
    $key_8355 = { d7 3d [2] a3 25 [2] e4 27 [2] a3 36 [2] ed 3a [2] e1 30 [2] f6 3b [2] ed 75 [2] d0 }

  condition:
    any of them
}