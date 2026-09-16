rule TTP_XOR_MULT_DOSStub_8956 {
  strings:
    $key_8956 = { dd 3e [2] a9 26 [2] ee 24 [2] a9 35 [2] e7 39 [2] eb 33 [2] fc 38 [2] e7 76 [2] da }

  condition:
    any of them
}