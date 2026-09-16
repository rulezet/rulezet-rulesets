rule TTP_XOR_MULT_DOSStub_9b2d {
  strings:
    $key_9b2d = { cf 45 [2] bb 5d [2] fc 5f [2] bb 4e [2] f5 42 [2] f9 48 [2] ee 43 [2] f5 0d [2] c8 }

  condition:
    any of them
}