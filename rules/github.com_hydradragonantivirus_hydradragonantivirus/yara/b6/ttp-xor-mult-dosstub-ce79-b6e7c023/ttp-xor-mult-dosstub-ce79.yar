rule TTP_XOR_MULT_DOSStub_ce79 {
  strings:
    $key_ce79 = { 9a 11 [2] ee 09 [2] a9 0b [2] ee 1a [2] a0 16 [2] ac 1c [2] bb 17 [2] a0 59 [2] 9d }

  condition:
    any of them
}