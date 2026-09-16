rule TTP_XOR_MULT_DOSStub_92ee {
  strings:
    $key_92ee = { c6 86 [2] b2 9e [2] f5 9c [2] b2 8d [2] fc 81 [2] f0 8b [2] e7 80 [2] fc ce [2] c1 }

  condition:
    any of them
}