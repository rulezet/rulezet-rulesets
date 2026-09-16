rule TTP_XOR_MULT_DOSStub_80b5 {
  strings:
    $key_80b5 = { d4 dd [2] a0 c5 [2] e7 c7 [2] a0 d6 [2] ee da [2] e2 d0 [2] f5 db [2] ee 95 [2] d3 }

  condition:
    any of them
}