rule TTP_XOR_MULT_DOSStub_8625 {
  strings:
    $key_8625 = { d2 4d [2] a6 55 [2] e1 57 [2] a6 46 [2] e8 4a [2] e4 40 [2] f3 4b [2] e8 05 [2] d5 }

  condition:
    any of them
}