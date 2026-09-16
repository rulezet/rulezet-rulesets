rule TTP_XOR_MULT_DOSStub_89e4 {
  strings:
    $key_89e4 = { dd 8c [2] a9 94 [2] ee 96 [2] a9 87 [2] e7 8b [2] eb 81 [2] fc 8a [2] e7 c4 [2] da }

  condition:
    any of them
}