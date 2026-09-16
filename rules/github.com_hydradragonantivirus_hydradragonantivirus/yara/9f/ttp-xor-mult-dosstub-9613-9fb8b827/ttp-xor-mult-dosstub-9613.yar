rule TTP_XOR_MULT_DOSStub_9613 {
  strings:
    $key_9613 = { c2 7b [2] b6 63 [2] f1 61 [2] b6 70 [2] f8 7c [2] f4 76 [2] e3 7d [2] f8 33 [2] c5 }

  condition:
    any of them
}