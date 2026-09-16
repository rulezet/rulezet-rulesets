rule TTP_XOR_MULT_DOSStub_896e {
  strings:
    $key_896e = { dd 06 [2] a9 1e [2] ee 1c [2] a9 0d [2] e7 01 [2] eb 0b [2] fc 00 [2] e7 4e [2] da }

  condition:
    any of them
}