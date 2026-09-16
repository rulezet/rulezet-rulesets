rule TTP_XOR_MULT_DOSStub_cee6 {
  strings:
    $key_cee6 = { 9a 8e [2] ee 96 [2] a9 94 [2] ee 85 [2] a0 89 [2] ac 83 [2] bb 88 [2] a0 c6 [2] 9d }

  condition:
    any of them
}