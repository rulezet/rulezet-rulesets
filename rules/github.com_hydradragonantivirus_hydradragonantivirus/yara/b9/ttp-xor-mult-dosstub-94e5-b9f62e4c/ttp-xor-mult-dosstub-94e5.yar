rule TTP_XOR_MULT_DOSStub_94e5 {
  strings:
    $key_94e5 = { c0 8d [2] b4 95 [2] f3 97 [2] b4 86 [2] fa 8a [2] f6 80 [2] e1 8b [2] fa c5 [2] c7 }

  condition:
    any of them
}