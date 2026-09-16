rule TTP_XOR_MULT_DOSStub_cefd {
  strings:
    $key_cefd = { 9a 95 [2] ee 8d [2] a9 8f [2] ee 9e [2] a0 92 [2] ac 98 [2] bb 93 [2] a0 dd [2] 9d }

  condition:
    any of them
}