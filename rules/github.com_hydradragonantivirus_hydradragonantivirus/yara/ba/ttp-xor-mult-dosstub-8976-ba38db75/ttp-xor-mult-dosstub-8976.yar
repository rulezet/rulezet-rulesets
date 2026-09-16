rule TTP_XOR_MULT_DOSStub_8976 {
  strings:
    $key_8976 = { dd 1e [2] a9 06 [2] ee 04 [2] a9 15 [2] e7 19 [2] eb 13 [2] fc 18 [2] e7 56 [2] da }

  condition:
    any of them
}