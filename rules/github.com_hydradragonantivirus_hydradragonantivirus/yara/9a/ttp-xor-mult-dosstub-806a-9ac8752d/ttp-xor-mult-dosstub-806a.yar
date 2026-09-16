rule TTP_XOR_MULT_DOSStub_806a {
  strings:
    $key_806a = { d4 02 [2] a0 1a [2] e7 18 [2] a0 09 [2] ee 05 [2] e2 0f [2] f5 04 [2] ee 4a [2] d3 }

  condition:
    any of them
}