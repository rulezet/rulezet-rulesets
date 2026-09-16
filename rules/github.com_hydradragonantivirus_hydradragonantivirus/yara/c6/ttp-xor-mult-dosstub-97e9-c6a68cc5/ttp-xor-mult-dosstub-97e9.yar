rule TTP_XOR_MULT_DOSStub_97e9 {
  strings:
    $key_97e9 = { c3 81 [2] b7 99 [2] f0 9b [2] b7 8a [2] f9 86 [2] f5 8c [2] e2 87 [2] f9 c9 [2] c4 }

  condition:
    any of them
}