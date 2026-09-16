rule TTP_XOR_MULT_DOSStub_ce50 {
  strings:
    $key_ce50 = { 9a 38 [2] ee 20 [2] a9 22 [2] ee 33 [2] a0 3f [2] ac 35 [2] bb 3e [2] a0 70 [2] 9d }

  condition:
    any of them
}