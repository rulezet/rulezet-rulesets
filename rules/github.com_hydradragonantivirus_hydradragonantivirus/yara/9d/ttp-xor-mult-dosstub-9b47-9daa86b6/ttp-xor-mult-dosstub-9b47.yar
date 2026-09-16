rule TTP_XOR_MULT_DOSStub_9b47 {
  strings:
    $key_9b47 = { cf 2f [2] bb 37 [2] fc 35 [2] bb 24 [2] f5 28 [2] f9 22 [2] ee 29 [2] f5 67 [2] c8 }

  condition:
    any of them
}