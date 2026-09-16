rule TTP_XOR_MULT_DOSStub_89f9 {
  strings:
    $key_89f9 = { dd 91 [2] a9 89 [2] ee 8b [2] a9 9a [2] e7 96 [2] eb 9c [2] fc 97 [2] e7 d9 [2] da }

  condition:
    any of them
}