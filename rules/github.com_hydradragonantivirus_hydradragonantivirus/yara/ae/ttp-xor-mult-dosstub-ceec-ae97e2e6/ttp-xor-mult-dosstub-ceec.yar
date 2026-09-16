rule TTP_XOR_MULT_DOSStub_ceec {
  strings:
    $key_ceec = { 9a 84 [2] ee 9c [2] a9 9e [2] ee 8f [2] a0 83 [2] ac 89 [2] bb 82 [2] a0 cc [2] 9d }

  condition:
    any of them
}