rule TTP_XOR_MULT_DOSStub_97e3 {
  strings:
    $key_97e3 = { c3 8b [2] b7 93 [2] f0 91 [2] b7 80 [2] f9 8c [2] f5 86 [2] e2 8d [2] f9 c3 [2] c4 }

  condition:
    any of them
}