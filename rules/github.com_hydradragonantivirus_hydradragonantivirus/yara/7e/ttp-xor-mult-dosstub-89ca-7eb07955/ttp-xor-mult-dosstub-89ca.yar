rule TTP_XOR_MULT_DOSStub_89ca {
  strings:
    $key_89ca = { dd a2 [2] a9 ba [2] ee b8 [2] a9 a9 [2] e7 a5 [2] eb af [2] fc a4 [2] e7 ea [2] da }

  condition:
    any of them
}