rule TTP_XOR_MULT_DOSStub_80ba {
  strings:
    $key_80ba = { d4 d2 [2] a0 ca [2] e7 c8 [2] a0 d9 [2] ee d5 [2] e2 df [2] f5 d4 [2] ee 9a [2] d3 }

  condition:
    any of them
}