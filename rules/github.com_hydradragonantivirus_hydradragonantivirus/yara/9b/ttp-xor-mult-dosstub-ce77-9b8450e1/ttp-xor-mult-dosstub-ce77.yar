rule TTP_XOR_MULT_DOSStub_ce77 {
  strings:
    $key_ce77 = { 9a 1f [2] ee 07 [2] a9 05 [2] ee 14 [2] a0 18 [2] ac 12 [2] bb 19 [2] a0 57 [2] 9d }

  condition:
    any of them
}