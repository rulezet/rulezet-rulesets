rule TTP_XOR_MULT_DOSStub_8374 {
  strings:
    $key_8374 = { d7 1c [2] a3 04 [2] e4 06 [2] a3 17 [2] ed 1b [2] e1 11 [2] f6 1a [2] ed 54 [2] d0 }

  condition:
    any of them
}