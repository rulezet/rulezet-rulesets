rule TTP_XOR_MULT_DOSStub_80fd {
  strings:
    $key_80fd = { d4 95 [2] a0 8d [2] e7 8f [2] a0 9e [2] ee 92 [2] e2 98 [2] f5 93 [2] ee dd [2] d3 }

  condition:
    any of them
}