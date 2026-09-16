rule TTP_XOR_MULT_DOSStub_ce47 {
  strings:
    $key_ce47 = { 9a 2f [2] ee 37 [2] a9 35 [2] ee 24 [2] a0 28 [2] ac 22 [2] bb 29 [2] a0 67 [2] 9d }

  condition:
    any of them
}