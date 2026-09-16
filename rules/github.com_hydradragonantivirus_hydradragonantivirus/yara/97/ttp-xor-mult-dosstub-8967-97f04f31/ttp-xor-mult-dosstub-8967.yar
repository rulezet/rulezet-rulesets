rule TTP_XOR_MULT_DOSStub_8967 {
  strings:
    $key_8967 = { dd 0f [2] a9 17 [2] ee 15 [2] a9 04 [2] e7 08 [2] eb 02 [2] fc 09 [2] e7 47 [2] da }

  condition:
    any of them
}