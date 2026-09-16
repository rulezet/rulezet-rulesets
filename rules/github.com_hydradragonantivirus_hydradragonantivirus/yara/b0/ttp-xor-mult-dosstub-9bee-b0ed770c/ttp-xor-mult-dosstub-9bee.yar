rule TTP_XOR_MULT_DOSStub_9bee {
  strings:
    $key_9bee = { cf 86 [2] bb 9e [2] fc 9c [2] bb 8d [2] f5 81 [2] f9 8b [2] ee 80 [2] f5 ce [2] c8 }

  condition:
    any of them
}