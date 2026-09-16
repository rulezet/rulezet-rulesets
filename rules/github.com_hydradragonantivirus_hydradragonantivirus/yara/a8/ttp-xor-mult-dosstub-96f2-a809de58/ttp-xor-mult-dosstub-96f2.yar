rule TTP_XOR_MULT_DOSStub_96f2 {
  strings:
    $key_96f2 = { c2 9a [2] b6 82 [2] f1 80 [2] b6 91 [2] f8 9d [2] f4 97 [2] e3 9c [2] f8 d2 [2] c5 }

  condition:
    any of them
}