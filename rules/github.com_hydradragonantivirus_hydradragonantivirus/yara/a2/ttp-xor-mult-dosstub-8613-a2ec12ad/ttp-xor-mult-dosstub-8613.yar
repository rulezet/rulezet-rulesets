rule TTP_XOR_MULT_DOSStub_8613 {
  strings:
    $key_8613 = { d2 7b [2] a6 63 [2] e1 61 [2] a6 70 [2] e8 7c [2] e4 76 [2] f3 7d [2] e8 33 [2] d5 }

  condition:
    any of them
}