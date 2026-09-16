rule TTP_XOR_MULT_DOSStub_9b04 {
  strings:
    $key_9b04 = { cf 6c [2] bb 74 [2] fc 76 [2] bb 67 [2] f5 6b [2] f9 61 [2] ee 6a [2] f5 24 [2] c8 }

  condition:
    any of them
}