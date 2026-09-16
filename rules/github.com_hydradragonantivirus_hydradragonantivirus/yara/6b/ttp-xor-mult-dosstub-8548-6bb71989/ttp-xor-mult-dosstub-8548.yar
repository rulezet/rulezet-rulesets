rule TTP_XOR_MULT_DOSStub_8548 {
  strings:
    $key_8548 = { d1 20 [2] a5 38 [2] e2 3a [2] a5 2b [2] eb 27 [2] e7 2d [2] f0 26 [2] eb 68 [2] d6 }

  condition:
    any of them
}