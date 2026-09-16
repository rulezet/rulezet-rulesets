rule TTP_XOR_MULT_DOSStub_9b2c {
  strings:
    $key_9b2c = { cf 44 [2] bb 5c [2] fc 5e [2] bb 4f [2] f5 43 [2] f9 49 [2] ee 42 [2] f5 0c [2] c8 }

  condition:
    any of them
}