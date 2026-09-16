rule TTP_XOR_MULT_DOSStub_96ee {
  strings:
    $key_96ee = { c2 86 [2] b6 9e [2] f1 9c [2] b6 8d [2] f8 81 [2] f4 8b [2] e3 80 [2] f8 ce [2] c5 }

  condition:
    any of them
}