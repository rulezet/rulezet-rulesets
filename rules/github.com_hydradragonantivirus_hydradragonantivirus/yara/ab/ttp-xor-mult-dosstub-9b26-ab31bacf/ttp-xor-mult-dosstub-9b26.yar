rule TTP_XOR_MULT_DOSStub_9b26 {
  strings:
    $key_9b26 = { cf 4e [2] bb 56 [2] fc 54 [2] bb 45 [2] f5 49 [2] f9 43 [2] ee 48 [2] f5 06 [2] c8 }

  condition:
    any of them
}