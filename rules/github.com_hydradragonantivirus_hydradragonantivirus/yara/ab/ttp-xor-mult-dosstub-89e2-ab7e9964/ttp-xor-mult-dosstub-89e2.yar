rule TTP_XOR_MULT_DOSStub_89e2 {
  strings:
    $key_89e2 = { dd 8a [2] a9 92 [2] ee 90 [2] a9 81 [2] e7 8d [2] eb 87 [2] fc 8c [2] e7 c2 [2] da }

  condition:
    any of them
}