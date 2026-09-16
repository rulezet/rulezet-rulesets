rule TTP_XOR_MULT_DOSStub_89e9 {
  strings:
    $key_89e9 = { dd 81 [2] a9 99 [2] ee 9b [2] a9 8a [2] e7 86 [2] eb 8c [2] fc 87 [2] e7 c9 [2] da }

  condition:
    any of them
}