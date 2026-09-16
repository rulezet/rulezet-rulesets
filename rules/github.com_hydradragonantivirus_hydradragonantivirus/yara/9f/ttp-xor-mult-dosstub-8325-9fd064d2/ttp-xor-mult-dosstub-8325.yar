rule TTP_XOR_MULT_DOSStub_8325 {
  strings:
    $key_8325 = { d7 4d [2] a3 55 [2] e4 57 [2] a3 46 [2] ed 4a [2] e1 40 [2] f6 4b [2] ed 05 [2] d0 }

  condition:
    any of them
}