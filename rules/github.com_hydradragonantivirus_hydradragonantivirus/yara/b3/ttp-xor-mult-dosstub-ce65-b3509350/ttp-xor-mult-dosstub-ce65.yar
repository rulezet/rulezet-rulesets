rule TTP_XOR_MULT_DOSStub_ce65 {
  strings:
    $key_ce65 = { 9a 0d [2] ee 15 [2] a9 17 [2] ee 06 [2] a0 0a [2] ac 00 [2] bb 0b [2] a0 45 [2] 9d }

  condition:
    any of them
}