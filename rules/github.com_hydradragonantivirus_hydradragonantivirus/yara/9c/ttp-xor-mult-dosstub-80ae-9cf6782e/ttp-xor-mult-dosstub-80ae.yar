rule TTP_XOR_MULT_DOSStub_80ae {
  strings:
    $key_80ae = { d4 c6 [2] a0 de [2] e7 dc [2] a0 cd [2] ee c1 [2] e2 cb [2] f5 c0 [2] ee 8e [2] d3 }

  condition:
    any of them
}