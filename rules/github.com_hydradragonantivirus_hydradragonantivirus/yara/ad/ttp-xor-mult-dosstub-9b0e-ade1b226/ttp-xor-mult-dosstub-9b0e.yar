rule TTP_XOR_MULT_DOSStub_9b0e {
  strings:
    $key_9b0e = { cf 66 [2] bb 7e [2] fc 7c [2] bb 6d [2] f5 61 [2] f9 6b [2] ee 60 [2] f5 2e [2] c8 }

  condition:
    any of them
}