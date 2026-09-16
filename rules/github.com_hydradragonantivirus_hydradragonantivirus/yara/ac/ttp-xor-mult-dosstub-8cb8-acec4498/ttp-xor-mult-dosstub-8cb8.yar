rule TTP_XOR_MULT_DOSStub_8cb8 {
  strings:
    $key_8cb8 = { d8 d0 [2] ac c8 [2] eb ca [2] ac db [2] e2 d7 [2] ee dd [2] f9 d6 [2] e2 98 [2] df }

  condition:
    any of them
}