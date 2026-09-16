rule TTP_XOR_MULT_DOSStub_8ca5 {
  strings:
    $key_8ca5 = { d8 cd [2] ac d5 [2] eb d7 [2] ac c6 [2] e2 ca [2] ee c0 [2] f9 cb [2] e2 85 [2] df }

  condition:
    any of them
}