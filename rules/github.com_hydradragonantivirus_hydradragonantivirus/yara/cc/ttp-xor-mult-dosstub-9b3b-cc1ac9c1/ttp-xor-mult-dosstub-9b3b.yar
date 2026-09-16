rule TTP_XOR_MULT_DOSStub_9b3b {
  strings:
    $key_9b3b = { cf 53 [2] bb 4b [2] fc 49 [2] bb 58 [2] f5 54 [2] f9 5e [2] ee 55 [2] f5 1b [2] c8 }

  condition:
    any of them
}