rule TTP_XOR_MULT_DOSStub_ce60 {
  strings:
    $key_ce60 = { 9a 08 [2] ee 10 [2] a9 12 [2] ee 03 [2] a0 0f [2] ac 05 [2] bb 0e [2] a0 40 [2] 9d }

  condition:
    any of them
}