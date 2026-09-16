rule TTP_XOR_MULT_DOSStub_8917 {
  strings:
    $key_8917 = { dd 7f [2] a9 67 [2] ee 65 [2] a9 74 [2] e7 78 [2] eb 72 [2] fc 79 [2] e7 37 [2] da }

  condition:
    any of them
}