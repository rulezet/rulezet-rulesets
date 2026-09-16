rule TTP_XOR_MULT_DOSStub_8305 {
  strings:
    $key_8305 = { d7 6d [2] a3 75 [2] e4 77 [2] a3 66 [2] ed 6a [2] e1 60 [2] f6 6b [2] ed 25 [2] d0 }

  condition:
    any of them
}