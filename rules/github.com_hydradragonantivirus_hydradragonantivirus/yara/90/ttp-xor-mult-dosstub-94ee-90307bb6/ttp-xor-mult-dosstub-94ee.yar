rule TTP_XOR_MULT_DOSStub_94ee {
  strings:
    $key_94ee = { c0 86 [2] b4 9e [2] f3 9c [2] b4 8d [2] fa 81 [2] f6 8b [2] e1 80 [2] fa ce [2] c7 }

  condition:
    any of them
}