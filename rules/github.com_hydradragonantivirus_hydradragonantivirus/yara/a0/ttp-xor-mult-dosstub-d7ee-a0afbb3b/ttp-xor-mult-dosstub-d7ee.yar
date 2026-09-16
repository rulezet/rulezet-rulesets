rule TTP_XOR_MULT_DOSStub_d7ee {
  strings:
    $key_d7ee = { 83 86 [2] f7 9e [2] b0 9c [2] f7 8d [2] b9 81 [2] b5 8b [2] a2 80 [2] b9 ce [2] 84 }

  condition:
    any of them
}