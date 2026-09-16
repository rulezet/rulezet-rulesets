rule TTP_XOR_MULT_DOSStub_ce11 {
  strings:
    $key_ce11 = { 9a 79 [2] ee 61 [2] a9 63 [2] ee 72 [2] a0 7e [2] ac 74 [2] bb 7f [2] a0 31 [2] 9d }

  condition:
    any of them
}