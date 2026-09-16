rule TTP_XOR_MULT_DOSStub_97f4 {
  strings:
    $key_97f4 = { c3 9c [2] b7 84 [2] f0 86 [2] b7 97 [2] f9 9b [2] f5 91 [2] e2 9a [2] f9 d4 [2] c4 }

  condition:
    any of them
}