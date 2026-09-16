rule TTP_XOR_MULT_DOSStub_97e5 {
  strings:
    $key_97e5 = { c3 8d [2] b7 95 [2] f0 97 [2] b7 86 [2] f9 8a [2] f5 80 [2] e2 8b [2] f9 c5 [2] c4 }

  condition:
    any of them
}