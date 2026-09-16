rule TTP_XOR_MULT_DOSStub_9beb {
  strings:
    $key_9beb = { cf 83 [2] bb 9b [2] fc 99 [2] bb 88 [2] f5 84 [2] f9 8e [2] ee 85 [2] f5 cb [2] c8 }

  condition:
    any of them
}