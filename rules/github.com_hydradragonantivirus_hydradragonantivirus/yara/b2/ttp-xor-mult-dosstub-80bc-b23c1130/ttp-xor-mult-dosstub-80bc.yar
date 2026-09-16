rule TTP_XOR_MULT_DOSStub_80bc {
  strings:
    $key_80bc = { d4 d4 [2] a0 cc [2] e7 ce [2] a0 df [2] ee d3 [2] e2 d9 [2] f5 d2 [2] ee 9c [2] d3 }

  condition:
    any of them
}