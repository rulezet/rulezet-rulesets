rule TTP_XOR_MULT_DOSStub_9b53 {
  strings:
    $key_9b53 = { cf 3b [2] bb 23 [2] fc 21 [2] bb 30 [2] f5 3c [2] f9 36 [2] ee 3d [2] f5 73 [2] c8 }

  condition:
    any of them
}