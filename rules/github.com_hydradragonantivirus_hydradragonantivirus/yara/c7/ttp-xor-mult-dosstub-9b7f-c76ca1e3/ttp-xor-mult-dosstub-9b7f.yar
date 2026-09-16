rule TTP_XOR_MULT_DOSStub_9b7f {
  strings:
    $key_9b7f = { cf 17 [2] bb 0f [2] fc 0d [2] bb 1c [2] f5 10 [2] f9 1a [2] ee 11 [2] f5 5f [2] c8 }

  condition:
    any of them
}