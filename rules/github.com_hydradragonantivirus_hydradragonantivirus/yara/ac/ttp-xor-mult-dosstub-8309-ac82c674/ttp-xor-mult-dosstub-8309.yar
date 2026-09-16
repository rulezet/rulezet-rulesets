rule TTP_XOR_MULT_DOSStub_8309 {
  strings:
    $key_8309 = { d7 61 [2] a3 79 [2] e4 7b [2] a3 6a [2] ed 66 [2] e1 6c [2] f6 67 [2] ed 29 [2] d0 }

  condition:
    any of them
}