rule TTP_XOR_MULT_DOSStub_9bf1 {
  strings:
    $key_9bf1 = { cf 99 [2] bb 81 [2] fc 83 [2] bb 92 [2] f5 9e [2] f9 94 [2] ee 9f [2] f5 d1 [2] c8 }

  condition:
    any of them
}