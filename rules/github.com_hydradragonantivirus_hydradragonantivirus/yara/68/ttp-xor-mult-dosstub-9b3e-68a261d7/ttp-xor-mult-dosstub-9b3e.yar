rule TTP_XOR_MULT_DOSStub_9b3e {
  strings:
    $key_9b3e = { cf 56 [2] bb 4e [2] fc 4c [2] bb 5d [2] f5 51 [2] f9 5b [2] ee 50 [2] f5 1e [2] c8 }

  condition:
    any of them
}