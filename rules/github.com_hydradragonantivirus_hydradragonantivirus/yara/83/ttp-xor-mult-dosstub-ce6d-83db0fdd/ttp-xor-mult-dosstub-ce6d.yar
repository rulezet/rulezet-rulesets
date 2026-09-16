rule TTP_XOR_MULT_DOSStub_ce6d {
  strings:
    $key_ce6d = { 9a 05 [2] ee 1d [2] a9 1f [2] ee 0e [2] a0 02 [2] ac 08 [2] bb 03 [2] a0 4d [2] 9d }

  condition:
    any of them
}