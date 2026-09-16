rule TTP_XOR_MULT_DOSStub_84ee {
  strings:
    $key_84ee = { d0 86 [2] a4 9e [2] e3 9c [2] a4 8d [2] ea 81 [2] e6 8b [2] f1 80 [2] ea ce [2] d7 }

  condition:
    any of them
}