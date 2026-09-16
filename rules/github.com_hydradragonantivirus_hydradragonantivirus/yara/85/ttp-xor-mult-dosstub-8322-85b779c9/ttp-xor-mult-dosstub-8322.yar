rule TTP_XOR_MULT_DOSStub_8322 {
  strings:
    $key_8322 = { d7 4a [2] a3 52 [2] e4 50 [2] a3 41 [2] ed 4d [2] e1 47 [2] f6 4c [2] ed 02 [2] d0 }

  condition:
    any of them
}