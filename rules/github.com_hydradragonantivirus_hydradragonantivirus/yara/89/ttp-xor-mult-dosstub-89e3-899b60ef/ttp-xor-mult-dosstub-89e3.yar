rule TTP_XOR_MULT_DOSStub_89e3 {
  strings:
    $key_89e3 = { dd 8b [2] a9 93 [2] ee 91 [2] a9 80 [2] e7 8c [2] eb 86 [2] fc 8d [2] e7 c3 [2] da }

  condition:
    any of them
}