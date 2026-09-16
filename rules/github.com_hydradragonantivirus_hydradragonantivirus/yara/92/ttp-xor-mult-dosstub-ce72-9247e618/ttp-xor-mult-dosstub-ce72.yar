rule TTP_XOR_MULT_DOSStub_ce72 {
  strings:
    $key_ce72 = { 9a 1a [2] ee 02 [2] a9 00 [2] ee 11 [2] a0 1d [2] ac 17 [2] bb 1c [2] a0 52 [2] 9d }

  condition:
    any of them
}