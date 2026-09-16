rule TTP_XOR_MULT_DOSStub_8c98 {
  strings:
    $key_8c98 = { d8 f0 [2] ac e8 [2] eb ea [2] ac fb [2] e2 f7 [2] ee fd [2] f9 f6 [2] e2 b8 [2] df }

  condition:
    any of them
}