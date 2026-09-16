rule TTP_XOR_MULT_DOSStub_9b46 {
  strings:
    $key_9b46 = { cf 2e [2] bb 36 [2] fc 34 [2] bb 25 [2] f5 29 [2] f9 23 [2] ee 28 [2] f5 66 [2] c8 }

  condition:
    any of them
}