rule TTP_XOR_MULT_DOSStub_9b6f {
  strings:
    $key_9b6f = { cf 07 [2] bb 1f [2] fc 1d [2] bb 0c [2] f5 00 [2] f9 0a [2] ee 01 [2] f5 4f [2] c8 }

  condition:
    any of them
}