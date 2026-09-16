rule TTP_XOR_MULT_DOSStub_8925 {
  strings:
    $key_8925 = { dd 4d [2] a9 55 [2] ee 57 [2] a9 46 [2] e7 4a [2] eb 40 [2] fc 4b [2] e7 05 [2] da }

  condition:
    any of them
}