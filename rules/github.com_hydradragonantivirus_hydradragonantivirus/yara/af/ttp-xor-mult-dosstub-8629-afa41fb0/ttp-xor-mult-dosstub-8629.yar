rule TTP_XOR_MULT_DOSStub_8629 {
  strings:
    $key_8629 = { d2 41 [2] a6 59 [2] e1 5b [2] a6 4a [2] e8 46 [2] e4 4c [2] f3 47 [2] e8 09 [2] d5 }

  condition:
    any of them
}