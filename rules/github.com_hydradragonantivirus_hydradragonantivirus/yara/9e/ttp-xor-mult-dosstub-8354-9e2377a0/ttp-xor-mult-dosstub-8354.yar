rule TTP_XOR_MULT_DOSStub_8354 {
  strings:
    $key_8354 = { d7 3c [2] a3 24 [2] e4 26 [2] a3 37 [2] ed 3b [2] e1 31 [2] f6 3a [2] ed 74 [2] d0 }

  condition:
    any of them
}