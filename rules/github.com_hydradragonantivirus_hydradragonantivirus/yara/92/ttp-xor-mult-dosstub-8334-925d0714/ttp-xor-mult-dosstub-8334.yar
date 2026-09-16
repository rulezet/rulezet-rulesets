rule TTP_XOR_MULT_DOSStub_8334 {
  strings:
    $key_8334 = { d7 5c [2] a3 44 [2] e4 46 [2] a3 57 [2] ed 5b [2] e1 51 [2] f6 5a [2] ed 14 [2] d0 }

  condition:
    any of them
}