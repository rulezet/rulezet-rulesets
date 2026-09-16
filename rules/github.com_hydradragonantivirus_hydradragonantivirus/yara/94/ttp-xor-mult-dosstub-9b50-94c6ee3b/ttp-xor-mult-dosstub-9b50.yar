rule TTP_XOR_MULT_DOSStub_9b50 {
  strings:
    $key_9b50 = { cf 38 [2] bb 20 [2] fc 22 [2] bb 33 [2] f5 3f [2] f9 35 [2] ee 3e [2] f5 70 [2] c8 }

  condition:
    any of them
}