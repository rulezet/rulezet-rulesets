rule TTP_XOR_MULT_DOSStub_89ee {
  strings:
    $key_89ee = { dd 86 [2] a9 9e [2] ee 9c [2] a9 8d [2] e7 81 [2] eb 8b [2] fc 80 [2] e7 ce [2] da }

  condition:
    any of them
}