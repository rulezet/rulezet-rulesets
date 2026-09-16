rule TTP_XOR_MULT_DOSStub_94e9 {
  strings:
    $key_94e9 = { c0 81 [2] b4 99 [2] f3 9b [2] b4 8a [2] fa 86 [2] f6 8c [2] e1 87 [2] fa c9 [2] c7 }

  condition:
    any of them
}