rule TTP_XOR_MULT_DOSStub_9626 {
  strings:
    $key_9626 = { c2 4e [2] b6 56 [2] f1 54 [2] b6 45 [2] f8 49 [2] f4 43 [2] e3 48 [2] f8 06 [2] c5 }

  condition:
    any of them
}