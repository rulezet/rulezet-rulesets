rule TTP_XOR_MULT_DOSStub_9b7a {
  strings:
    $key_9b7a = { cf 12 [2] bb 0a [2] fc 08 [2] bb 19 [2] f5 15 [2] f9 1f [2] ee 14 [2] f5 5a [2] c8 }

  condition:
    any of them
}