rule TTP_XOR_MULT_DOSStub_89f7 {
  strings:
    $key_89f7 = { dd 9f [2] a9 87 [2] ee 85 [2] a9 94 [2] e7 98 [2] eb 92 [2] fc 99 [2] e7 d7 [2] da }

  condition:
    any of them
}