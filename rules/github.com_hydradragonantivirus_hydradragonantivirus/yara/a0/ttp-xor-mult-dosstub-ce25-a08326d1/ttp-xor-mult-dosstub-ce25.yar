rule TTP_XOR_MULT_DOSStub_ce25 {
  strings:
    $key_ce25 = { 9a 4d [2] ee 55 [2] a9 57 [2] ee 46 [2] a0 4a [2] ac 40 [2] bb 4b [2] a0 05 [2] 9d }

  condition:
    any of them
}