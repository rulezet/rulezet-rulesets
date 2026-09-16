rule TTP_XOR_MULT_DOSStub_8936 {
  strings:
    $key_8936 = { dd 5e [2] a9 46 [2] ee 44 [2] a9 55 [2] e7 59 [2] eb 53 [2] fc 58 [2] e7 16 [2] da }

  condition:
    any of them
}