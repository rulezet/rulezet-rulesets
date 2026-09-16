rule TTP_XOR_MULT_DOSStub_ce0d {
  strings:
    $key_ce0d = { 9a 65 [2] ee 7d [2] a9 7f [2] ee 6e [2] a0 62 [2] ac 68 [2] bb 63 [2] a0 2d [2] 9d }

  condition:
    any of them
}