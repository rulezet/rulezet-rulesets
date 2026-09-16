rule TTP_XOR_MULT_DOSStub_8011 {
  strings:
    $key_8011 = { d4 79 [2] a0 61 [2] e7 63 [2] a0 72 [2] ee 7e [2] e2 74 [2] f5 7f [2] ee 31 [2] d3 }

  condition:
    any of them
}