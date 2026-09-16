rule TTP_XOR_MULT_DOSStub_ce41 {
  strings:
    $key_ce41 = { 9a 29 [2] ee 31 [2] a9 33 [2] ee 22 [2] a0 2e [2] ac 24 [2] bb 2f [2] a0 61 [2] 9d }

  condition:
    any of them
}