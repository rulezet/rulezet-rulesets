rule TTP_XOR_MULT_DOSStub_ce6b {
  strings:
    $key_ce6b = { 9a 03 [2] ee 1b [2] a9 19 [2] ee 08 [2] a0 04 [2] ac 0e [2] bb 05 [2] a0 4b [2] 9d }

  condition:
    any of them
}