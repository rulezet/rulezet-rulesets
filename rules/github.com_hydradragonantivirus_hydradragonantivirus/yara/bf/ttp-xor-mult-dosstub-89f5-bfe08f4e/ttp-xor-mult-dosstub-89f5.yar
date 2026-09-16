rule TTP_XOR_MULT_DOSStub_89f5 {
  strings:
    $key_89f5 = { dd 9d [2] a9 85 [2] ee 87 [2] a9 96 [2] e7 9a [2] eb 90 [2] fc 9b [2] e7 d5 [2] da }

  condition:
    any of them
}