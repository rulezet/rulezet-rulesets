rule TTP_XOR_MULT_DOSStub_9b76 {
  strings:
    $key_9b76 = { cf 1e [2] bb 06 [2] fc 04 [2] bb 15 [2] f5 19 [2] f9 13 [2] ee 18 [2] f5 56 [2] c8 }

  condition:
    any of them
}