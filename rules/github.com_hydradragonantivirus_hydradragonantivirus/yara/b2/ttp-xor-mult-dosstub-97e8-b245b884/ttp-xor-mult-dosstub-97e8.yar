rule TTP_XOR_MULT_DOSStub_97e8 {
  strings:
    $key_97e8 = { c3 80 [2] b7 98 [2] f0 9a [2] b7 8b [2] f9 87 [2] f5 8d [2] e2 86 [2] f9 c8 [2] c4 }

  condition:
    any of them
}