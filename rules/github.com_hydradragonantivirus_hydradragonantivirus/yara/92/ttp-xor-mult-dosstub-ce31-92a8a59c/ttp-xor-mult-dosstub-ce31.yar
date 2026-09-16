rule TTP_XOR_MULT_DOSStub_ce31 {
  strings:
    $key_ce31 = { 9a 59 [2] ee 41 [2] a9 43 [2] ee 52 [2] a0 5e [2] ac 54 [2] bb 5f [2] a0 11 [2] 9d }

  condition:
    any of them
}