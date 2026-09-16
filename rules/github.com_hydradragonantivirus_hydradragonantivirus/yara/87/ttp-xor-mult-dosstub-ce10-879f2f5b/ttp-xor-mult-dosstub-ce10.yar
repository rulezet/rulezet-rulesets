rule TTP_XOR_MULT_DOSStub_ce10 {
  strings:
    $key_ce10 = { 9a 78 [2] ee 60 [2] a9 62 [2] ee 73 [2] a0 7f [2] ac 75 [2] bb 7e [2] a0 30 [2] 9d }

  condition:
    any of them
}