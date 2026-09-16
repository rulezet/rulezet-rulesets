rule TTP_XOR_MULT_DOSStub_ce45 {
  strings:
    $key_ce45 = { 9a 2d [2] ee 35 [2] a9 37 [2] ee 26 [2] a0 2a [2] ac 20 [2] bb 2b [2] a0 65 [2] 9d }

  condition:
    any of them
}