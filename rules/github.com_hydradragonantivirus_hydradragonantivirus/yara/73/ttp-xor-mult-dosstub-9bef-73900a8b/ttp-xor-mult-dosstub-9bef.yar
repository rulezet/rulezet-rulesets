rule TTP_XOR_MULT_DOSStub_9bef {
  strings:
    $key_9bef = { cf 87 [2] bb 9f [2] fc 9d [2] bb 8c [2] f5 80 [2] f9 8a [2] ee 81 [2] f5 cf [2] c8 }

  condition:
    any of them
}