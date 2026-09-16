rule TTP_XOR_MULT_DOSStub_cefc {
  strings:
    $key_cefc = { 9a 94 [2] ee 8c [2] a9 8e [2] ee 9f [2] a0 93 [2] ac 99 [2] bb 92 [2] a0 dc [2] 9d }

  condition:
    any of them
}