rule TTP_XOR_MULT_DOSStub_9b1e {
  strings:
    $key_9b1e = { cf 76 [2] bb 6e [2] fc 6c [2] bb 7d [2] f5 71 [2] f9 7b [2] ee 70 [2] f5 3e [2] c8 }

  condition:
    any of them
}