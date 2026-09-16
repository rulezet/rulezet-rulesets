rule TTP_XOR_MULT_DOSStub_8916 {
  strings:
    $key_8916 = { dd 7e [2] a9 66 [2] ee 64 [2] a9 75 [2] e7 79 [2] eb 73 [2] fc 78 [2] e7 36 [2] da }

  condition:
    any of them
}