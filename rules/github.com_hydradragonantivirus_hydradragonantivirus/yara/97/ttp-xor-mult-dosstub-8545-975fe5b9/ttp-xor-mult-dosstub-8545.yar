rule TTP_XOR_MULT_DOSStub_8545 {
  strings:
    $key_8545 = { d1 2d [2] a5 35 [2] e2 37 [2] a5 26 [2] eb 2a [2] e7 20 [2] f0 2b [2] eb 65 [2] d6 }

  condition:
    any of them
}