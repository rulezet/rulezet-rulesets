rule TTP_XOR_MULT_DOSStub_9b7e {
  strings:
    $key_9b7e = { cf 16 [2] bb 0e [2] fc 0c [2] bb 1d [2] f5 11 [2] f9 1b [2] ee 10 [2] f5 5e [2] c8 }

  condition:
    any of them
}