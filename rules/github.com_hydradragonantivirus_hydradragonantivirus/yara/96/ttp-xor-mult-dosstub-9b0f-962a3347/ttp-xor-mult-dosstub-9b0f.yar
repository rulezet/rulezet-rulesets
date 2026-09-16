rule TTP_XOR_MULT_DOSStub_9b0f {
  strings:
    $key_9b0f = { cf 67 [2] bb 7f [2] fc 7d [2] bb 6c [2] f5 60 [2] f9 6a [2] ee 61 [2] f5 2f [2] c8 }

  condition:
    any of them
}