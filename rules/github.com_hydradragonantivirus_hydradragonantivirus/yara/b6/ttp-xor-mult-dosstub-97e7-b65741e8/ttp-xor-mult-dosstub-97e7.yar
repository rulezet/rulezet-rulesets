rule TTP_XOR_MULT_DOSStub_97e7 {
  strings:
    $key_97e7 = { c3 8f [2] b7 97 [2] f0 95 [2] b7 84 [2] f9 88 [2] f5 82 [2] e2 89 [2] f9 c7 [2] c4 }

  condition:
    any of them
}