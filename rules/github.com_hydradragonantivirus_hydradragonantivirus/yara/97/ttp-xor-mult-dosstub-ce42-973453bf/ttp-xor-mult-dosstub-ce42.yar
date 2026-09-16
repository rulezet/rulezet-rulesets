rule TTP_XOR_MULT_DOSStub_ce42 {
  strings:
    $key_ce42 = { 9a 2a [2] ee 32 [2] a9 30 [2] ee 21 [2] a0 2d [2] ac 27 [2] bb 2c [2] a0 62 [2] 9d }

  condition:
    any of them
}