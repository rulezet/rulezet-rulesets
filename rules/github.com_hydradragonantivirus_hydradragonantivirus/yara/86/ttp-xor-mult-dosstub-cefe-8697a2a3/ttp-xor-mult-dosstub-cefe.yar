rule TTP_XOR_MULT_DOSStub_cefe {
  strings:
    $key_cefe = { 9a 96 [2] ee 8e [2] a9 8c [2] ee 9d [2] a0 91 [2] ac 9b [2] bb 90 [2] a0 de [2] 9d }

  condition:
    any of them
}