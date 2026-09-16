rule TTP_XOR_MULT_DOSStub_8cc8 {
  strings:
    $key_8cc8 = { d8 a0 [2] ac b8 [2] eb ba [2] ac ab [2] e2 a7 [2] ee ad [2] f9 a6 [2] e2 e8 [2] df }

  condition:
    any of them
}