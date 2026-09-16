rule TTP_XOR_MULT_DOSStub_ce04 {
  strings:
    $key_ce04 = { 9a 6c [2] ee 74 [2] a9 76 [2] ee 67 [2] a0 6b [2] ac 61 [2] bb 6a [2] a0 24 [2] 9d }

  condition:
    any of them
}