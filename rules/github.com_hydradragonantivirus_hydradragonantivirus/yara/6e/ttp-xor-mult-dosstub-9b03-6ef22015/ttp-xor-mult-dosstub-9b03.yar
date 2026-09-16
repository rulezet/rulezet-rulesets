rule TTP_XOR_MULT_DOSStub_9b03 {
  strings:
    $key_9b03 = { cf 6b [2] bb 73 [2] fc 71 [2] bb 60 [2] f5 6c [2] f9 66 [2] ee 6d [2] f5 23 [2] c8 }

  condition:
    any of them
}