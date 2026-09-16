rule TTP_XOR_MULT_DOSStub_ce63 {
  strings:
    $key_ce63 = { 9a 0b [2] ee 13 [2] a9 11 [2] ee 00 [2] a0 0c [2] ac 06 [2] bb 0d [2] a0 43 [2] 9d }

  condition:
    any of them
}