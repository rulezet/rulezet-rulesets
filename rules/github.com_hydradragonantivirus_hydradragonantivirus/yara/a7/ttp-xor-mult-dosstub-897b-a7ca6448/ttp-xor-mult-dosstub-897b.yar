rule TTP_XOR_MULT_DOSStub_897b {
  strings:
    $key_897b = { dd 13 [2] a9 0b [2] ee 09 [2] a9 18 [2] e7 14 [2] eb 1e [2] fc 15 [2] e7 5b [2] da }

  condition:
    any of them
}