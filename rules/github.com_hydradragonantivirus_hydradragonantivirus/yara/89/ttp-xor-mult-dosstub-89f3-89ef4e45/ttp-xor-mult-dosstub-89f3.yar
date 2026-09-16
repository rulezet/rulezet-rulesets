rule TTP_XOR_MULT_DOSStub_89f3 {
  strings:
    $key_89f3 = { dd 9b [2] a9 83 [2] ee 81 [2] a9 90 [2] e7 9c [2] eb 96 [2] fc 9d [2] e7 d3 [2] da }

  condition:
    any of them
}