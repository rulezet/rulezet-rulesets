rule TTP_XOR_MULT_DOSStub_8979 {
  strings:
    $key_8979 = { dd 11 [2] a9 09 [2] ee 0b [2] a9 1a [2] e7 16 [2] eb 1c [2] fc 17 [2] e7 59 [2] da }

  condition:
    any of them
}