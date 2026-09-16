rule TTP_XOR_MULT_DOSStub_8ca8 {
  strings:
    $key_8ca8 = { d8 c0 [2] ac d8 [2] eb da [2] ac cb [2] e2 c7 [2] ee cd [2] f9 c6 [2] e2 88 [2] df }

  condition:
    any of them
}