rule TTP_XOR_MULT_DOSStub_8cba {
  strings:
    $key_8cba = { d8 d2 [2] ac ca [2] eb c8 [2] ac d9 [2] e2 d5 [2] ee df [2] f9 d4 [2] e2 9a [2] df }

  condition:
    any of them
}