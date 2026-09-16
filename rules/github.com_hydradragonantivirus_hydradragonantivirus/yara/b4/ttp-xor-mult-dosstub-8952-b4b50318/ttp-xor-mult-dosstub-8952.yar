rule TTP_XOR_MULT_DOSStub_8952 {
  strings:
    $key_8952 = { dd 3a [2] a9 22 [2] ee 20 [2] a9 31 [2] e7 3d [2] eb 37 [2] fc 3c [2] e7 72 [2] da }

  condition:
    any of them
}