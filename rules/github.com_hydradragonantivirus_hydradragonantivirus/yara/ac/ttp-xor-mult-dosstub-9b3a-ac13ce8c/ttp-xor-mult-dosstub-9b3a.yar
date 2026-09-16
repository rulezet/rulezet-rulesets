rule TTP_XOR_MULT_DOSStub_9b3a {
  strings:
    $key_9b3a = { cf 52 [2] bb 4a [2] fc 48 [2] bb 59 [2] f5 55 [2] f9 5f [2] ee 54 [2] f5 1a [2] c8 }

  condition:
    any of them
}