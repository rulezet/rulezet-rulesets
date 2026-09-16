rule TTP_XOR_MULT_DOSStub_9bf5 {
  strings:
    $key_9bf5 = { cf 9d [2] bb 85 [2] fc 87 [2] bb 96 [2] f5 9a [2] f9 90 [2] ee 9b [2] f5 d5 [2] c8 }

  condition:
    any of them
}