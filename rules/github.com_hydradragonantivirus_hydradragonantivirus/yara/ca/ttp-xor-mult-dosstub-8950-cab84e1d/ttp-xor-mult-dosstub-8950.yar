rule TTP_XOR_MULT_DOSStub_8950 {
  strings:
    $key_8950 = { dd 38 [2] a9 20 [2] ee 22 [2] a9 33 [2] e7 3f [2] eb 35 [2] fc 3e [2] e7 70 [2] da }

  condition:
    any of them
}