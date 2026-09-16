rule TTP_XOR_MULT_DOSStub_ce61 {
  strings:
    $key_ce61 = { 9a 09 [2] ee 11 [2] a9 13 [2] ee 02 [2] a0 0e [2] ac 04 [2] bb 0f [2] a0 41 [2] 9d }

  condition:
    any of them
}