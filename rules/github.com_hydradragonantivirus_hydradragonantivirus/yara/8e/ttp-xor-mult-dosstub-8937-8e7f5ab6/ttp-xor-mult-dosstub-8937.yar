rule TTP_XOR_MULT_DOSStub_8937 {
  strings:
    $key_8937 = { dd 5f [2] a9 47 [2] ee 45 [2] a9 54 [2] e7 58 [2] eb 52 [2] fc 59 [2] e7 17 [2] da }

  condition:
    any of them
}