rule TTP_XOR_MULT_DOSStub_9b4a {
  strings:
    $key_9b4a = { cf 22 [2] bb 3a [2] fc 38 [2] bb 29 [2] f5 25 [2] f9 2f [2] ee 24 [2] f5 6a [2] c8 }

  condition:
    any of them
}