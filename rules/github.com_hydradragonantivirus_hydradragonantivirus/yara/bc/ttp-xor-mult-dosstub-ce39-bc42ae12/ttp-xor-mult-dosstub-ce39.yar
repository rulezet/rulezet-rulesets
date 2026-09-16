rule TTP_XOR_MULT_DOSStub_ce39 {
  strings:
    $key_ce39 = { 9a 51 [2] ee 49 [2] a9 4b [2] ee 5a [2] a0 56 [2] ac 5c [2] bb 57 [2] a0 19 [2] 9d }

  condition:
    any of them
}