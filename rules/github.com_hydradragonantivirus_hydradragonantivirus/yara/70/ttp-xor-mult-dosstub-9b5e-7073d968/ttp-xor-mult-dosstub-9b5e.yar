rule TTP_XOR_MULT_DOSStub_9b5e {
  strings:
    $key_9b5e = { cf 36 [2] bb 2e [2] fc 2c [2] bb 3d [2] f5 31 [2] f9 3b [2] ee 30 [2] f5 7e [2] c8 }

  condition:
    any of them
}