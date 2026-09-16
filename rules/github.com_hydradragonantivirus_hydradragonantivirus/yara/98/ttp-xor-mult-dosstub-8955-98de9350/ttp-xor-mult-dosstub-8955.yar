rule TTP_XOR_MULT_DOSStub_8955 {
  strings:
    $key_8955 = { dd 3d [2] a9 25 [2] ee 27 [2] a9 36 [2] e7 3a [2] eb 30 [2] fc 3b [2] e7 75 [2] da }

  condition:
    any of them
}