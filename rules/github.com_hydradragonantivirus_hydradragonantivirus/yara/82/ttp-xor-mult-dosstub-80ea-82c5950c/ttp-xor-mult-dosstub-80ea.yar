rule TTP_XOR_MULT_DOSStub_80ea {
  strings:
    $key_80ea = { d4 82 [2] a0 9a [2] e7 98 [2] a0 89 [2] ee 85 [2] e2 8f [2] f5 84 [2] ee ca [2] d3 }

  condition:
    any of them
}