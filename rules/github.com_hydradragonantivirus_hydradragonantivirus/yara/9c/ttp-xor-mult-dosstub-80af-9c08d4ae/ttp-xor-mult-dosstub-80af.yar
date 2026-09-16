rule TTP_XOR_MULT_DOSStub_80af {
  strings:
    $key_80af = { d4 c7 [2] a0 df [2] e7 dd [2] a0 cc [2] ee c0 [2] e2 ca [2] f5 c1 [2] ee 8f [2] d3 }

  condition:
    any of them
}