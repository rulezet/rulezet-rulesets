rule TTP_XOR_MULT_DOSStub_d1ee {
  strings:
    $key_d1ee = { 85 86 [2] f1 9e [2] b6 9c [2] f1 8d [2] bf 81 [2] b3 8b [2] a4 80 [2] bf ce [2] 82 }

  condition:
    any of them
}