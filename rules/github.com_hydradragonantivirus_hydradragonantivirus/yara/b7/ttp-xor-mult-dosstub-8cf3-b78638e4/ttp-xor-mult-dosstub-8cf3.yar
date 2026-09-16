rule TTP_XOR_MULT_DOSStub_8cf3 {
  strings:
    $key_8cf3 = { d8 9b [2] ac 83 [2] eb 81 [2] ac 90 [2] e2 9c [2] ee 96 [2] f9 9d [2] e2 d3 [2] df }

  condition:
    any of them
}