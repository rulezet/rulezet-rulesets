rule TTP_XOR_MULT_DOSStub_ce54 {
  strings:
    $key_ce54 = { 9a 3c [2] ee 24 [2] a9 26 [2] ee 37 [2] a0 3b [2] ac 31 [2] bb 3a [2] a0 74 [2] 9d }

  condition:
    any of them
}