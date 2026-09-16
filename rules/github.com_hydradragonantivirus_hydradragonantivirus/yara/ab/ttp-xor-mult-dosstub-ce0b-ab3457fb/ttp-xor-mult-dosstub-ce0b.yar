rule TTP_XOR_MULT_DOSStub_ce0b {
  strings:
    $key_ce0b = { 9a 63 [2] ee 7b [2] a9 79 [2] ee 68 [2] a0 64 [2] ac 6e [2] bb 65 [2] a0 2b [2] 9d }

  condition:
    any of them
}