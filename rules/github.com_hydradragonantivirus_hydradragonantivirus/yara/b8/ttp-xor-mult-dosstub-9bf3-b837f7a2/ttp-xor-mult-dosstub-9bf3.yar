rule TTP_XOR_MULT_DOSStub_9bf3 {
  strings:
    $key_9bf3 = { cf 9b [2] bb 83 [2] fc 81 [2] bb 90 [2] f5 9c [2] f9 96 [2] ee 9d [2] f5 d3 [2] c8 }

  condition:
    any of them
}