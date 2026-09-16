rule TTP_XOR_MULT_DOSStub_9bfc {
  strings:
    $key_9bfc = { cf 94 [2] bb 8c [2] fc 8e [2] bb 9f [2] f5 93 [2] f9 99 [2] ee 92 [2] f5 dc [2] c8 }

  condition:
    any of them
}