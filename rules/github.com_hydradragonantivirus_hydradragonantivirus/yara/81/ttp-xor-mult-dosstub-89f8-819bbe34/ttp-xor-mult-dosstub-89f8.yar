rule TTP_XOR_MULT_DOSStub_89f8 {
  strings:
    $key_89f8 = { dd 90 [2] a9 88 [2] ee 8a [2] a9 9b [2] e7 97 [2] eb 9d [2] fc 96 [2] e7 d8 [2] da }

  condition:
    any of them
}