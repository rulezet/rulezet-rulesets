rule TTP_XOR_MULT_DOSStub_8922 {
  strings:
    $key_8922 = { dd 4a [2] a9 52 [2] ee 50 [2] a9 41 [2] e7 4d [2] eb 47 [2] fc 4c [2] e7 02 [2] da }

  condition:
    any of them
}