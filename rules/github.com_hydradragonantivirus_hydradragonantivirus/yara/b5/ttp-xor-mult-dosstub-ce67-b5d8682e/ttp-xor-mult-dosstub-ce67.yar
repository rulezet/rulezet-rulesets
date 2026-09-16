rule TTP_XOR_MULT_DOSStub_ce67 {
  strings:
    $key_ce67 = { 9a 0f [2] ee 17 [2] a9 15 [2] ee 04 [2] a0 08 [2] ac 02 [2] bb 09 [2] a0 47 [2] 9d }

  condition:
    any of them
}