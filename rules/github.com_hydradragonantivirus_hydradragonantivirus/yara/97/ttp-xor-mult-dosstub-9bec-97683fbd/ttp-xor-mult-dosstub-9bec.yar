rule TTP_XOR_MULT_DOSStub_9bec {
  strings:
    $key_9bec = { cf 84 [2] bb 9c [2] fc 9e [2] bb 8f [2] f5 83 [2] f9 89 [2] ee 82 [2] f5 cc [2] c8 }

  condition:
    any of them
}