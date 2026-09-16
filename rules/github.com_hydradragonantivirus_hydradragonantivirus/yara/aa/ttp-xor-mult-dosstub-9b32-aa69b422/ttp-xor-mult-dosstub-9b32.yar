rule TTP_XOR_MULT_DOSStub_9b32 {
  strings:
    $key_9b32 = { cf 5a [2] bb 42 [2] fc 40 [2] bb 51 [2] f5 5d [2] f9 57 [2] ee 5c [2] f5 12 [2] c8 }

  condition:
    any of them
}