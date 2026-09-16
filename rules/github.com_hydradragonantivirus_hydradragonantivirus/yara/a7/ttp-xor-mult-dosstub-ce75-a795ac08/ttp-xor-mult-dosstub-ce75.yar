rule TTP_XOR_MULT_DOSStub_ce75 {
  strings:
    $key_ce75 = { 9a 1d [2] ee 05 [2] a9 07 [2] ee 16 [2] a0 1a [2] ac 10 [2] bb 1b [2] a0 55 [2] 9d }

  condition:
    any of them
}