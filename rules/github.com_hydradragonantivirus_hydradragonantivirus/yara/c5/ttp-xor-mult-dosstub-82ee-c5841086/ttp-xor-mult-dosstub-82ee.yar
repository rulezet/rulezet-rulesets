rule TTP_XOR_MULT_DOSStub_82ee {
  strings:
    $key_82ee = { d6 86 [2] a2 9e [2] e5 9c [2] a2 8d [2] ec 81 [2] e0 8b [2] f7 80 [2] ec ce [2] d1 }

  condition:
    any of them
}