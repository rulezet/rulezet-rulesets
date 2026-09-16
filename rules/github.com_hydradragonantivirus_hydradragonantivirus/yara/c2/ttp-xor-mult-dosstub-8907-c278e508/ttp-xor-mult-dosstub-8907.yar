rule TTP_XOR_MULT_DOSStub_8907 {
  strings:
    $key_8907 = { dd 6f [2] a9 77 [2] ee 75 [2] a9 64 [2] e7 68 [2] eb 62 [2] fc 69 [2] e7 27 [2] da }

  condition:
    any of them
}