rule TTP_XOR_MULT_DOSStub_89f1 {
  strings:
    $key_89f1 = { dd 99 [2] a9 81 [2] ee 83 [2] a9 92 [2] e7 9e [2] eb 94 [2] fc 9f [2] e7 d1 [2] da }

  condition:
    any of them
}