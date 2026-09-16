rule TTP_XOR_MULT_DOSStub_ce05 {
  strings:
    $key_ce05 = { 9a 6d [2] ee 75 [2] a9 77 [2] ee 66 [2] a0 6a [2] ac 60 [2] bb 6b [2] a0 25 [2] 9d }

  condition:
    any of them
}