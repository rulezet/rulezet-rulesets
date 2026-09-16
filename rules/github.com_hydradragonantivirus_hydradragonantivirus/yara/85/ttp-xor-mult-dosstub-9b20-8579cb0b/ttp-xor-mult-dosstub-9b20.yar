rule TTP_XOR_MULT_DOSStub_9b20 {
  strings:
    $key_9b20 = { cf 48 [2] bb 50 [2] fc 52 [2] bb 43 [2] f5 4f [2] f9 45 [2] ee 4e [2] f5 00 [2] c8 }

  condition:
    any of them
}