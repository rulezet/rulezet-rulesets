rule TTP_XOR_MULT_DOSStub_89dd {
  strings:
    $key_89dd = { dd b5 [2] a9 ad [2] ee af [2] a9 be [2] e7 b2 [2] eb b8 [2] fc b3 [2] e7 fd [2] da }

  condition:
    any of them
}