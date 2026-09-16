rule TTP_XOR_MULT_DOSStub_9677 {
  strings:
    $key_9677 = { c2 1f [2] b6 07 [2] f1 05 [2] b6 14 [2] f8 18 [2] f4 12 [2] e3 19 [2] f8 57 [2] c5 }

  condition:
    any of them
}