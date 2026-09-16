rule TTP_XOR_MULT_DOSStub_ce76 {
  strings:
    $key_ce76 = { 9a 1e [2] ee 06 [2] a9 04 [2] ee 15 [2] a0 19 [2] ac 13 [2] bb 18 [2] a0 56 [2] 9d }

  condition:
    any of them
}