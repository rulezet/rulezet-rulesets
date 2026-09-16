rule TTP_XOR_MULT_DOSStub_ce34 {
  strings:
    $key_ce34 = { 9a 5c [2] ee 44 [2] a9 46 [2] ee 57 [2] a0 5b [2] ac 51 [2] bb 5a [2] a0 14 [2] 9d }

  condition:
    any of them
}