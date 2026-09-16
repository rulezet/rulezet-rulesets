rule TTP_XOR_MULT_DOSStub_8951 {
  strings:
    $key_8951 = { dd 39 [2] a9 21 [2] ee 23 [2] a9 32 [2] e7 3e [2] eb 34 [2] fc 3f [2] e7 71 [2] da }

  condition:
    any of them
}