rule TTP_XOR_MULT_DOSStub_8971 {
  strings:
    $key_8971 = { dd 19 [2] a9 01 [2] ee 03 [2] a9 12 [2] e7 1e [2] eb 14 [2] fc 1f [2] e7 51 [2] da }

  condition:
    any of them
}