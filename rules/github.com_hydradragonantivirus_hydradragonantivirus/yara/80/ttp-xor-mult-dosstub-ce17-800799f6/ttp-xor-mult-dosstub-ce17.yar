rule TTP_XOR_MULT_DOSStub_ce17 {
  strings:
    $key_ce17 = { 9a 7f [2] ee 67 [2] a9 65 [2] ee 74 [2] a0 78 [2] ac 72 [2] bb 79 [2] a0 37 [2] 9d }

  condition:
    any of them
}