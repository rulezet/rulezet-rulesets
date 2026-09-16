rule TTP_XOR_MULT_DOSStub_8742 {
  strings:
    $key_8742 = { d3 2a [2] a7 32 [2] e0 30 [2] a7 21 [2] e9 2d [2] e5 27 [2] f2 2c [2] e9 62 [2] d4 }

  condition:
    any of them
}