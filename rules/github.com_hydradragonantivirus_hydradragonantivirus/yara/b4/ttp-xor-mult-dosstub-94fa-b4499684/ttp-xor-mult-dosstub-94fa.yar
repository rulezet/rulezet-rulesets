rule TTP_XOR_MULT_DOSStub_94fa {
  strings:
    $key_94fa = { c0 92 [2] b4 8a [2] f3 88 [2] b4 99 [2] fa 95 [2] f6 9f [2] e1 94 [2] fa da [2] c7 }

  condition:
    any of them
}