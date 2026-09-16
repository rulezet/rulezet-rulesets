rule TTP_XOR_MULT_DOSStub_9b4e {
  strings:
    $key_9b4e = { cf 26 [2] bb 3e [2] fc 3c [2] bb 2d [2] f5 21 [2] f9 2b [2] ee 20 [2] f5 6e [2] c8 }

  condition:
    any of them
}