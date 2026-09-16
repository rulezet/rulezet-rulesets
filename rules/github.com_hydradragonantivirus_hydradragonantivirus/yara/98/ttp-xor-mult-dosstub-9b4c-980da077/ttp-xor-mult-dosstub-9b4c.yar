rule TTP_XOR_MULT_DOSStub_9b4c {
  strings:
    $key_9b4c = { cf 24 [2] bb 3c [2] fc 3e [2] bb 2f [2] f5 23 [2] f9 29 [2] ee 22 [2] f5 6c [2] c8 }

  condition:
    any of them
}