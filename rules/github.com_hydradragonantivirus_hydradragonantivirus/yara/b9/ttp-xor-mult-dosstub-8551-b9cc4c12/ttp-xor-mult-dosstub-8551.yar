rule TTP_XOR_MULT_DOSStub_8551 {
  strings:
    $key_8551 = { d1 39 [2] a5 21 [2] e2 23 [2] a5 32 [2] eb 3e [2] e7 34 [2] f0 3f [2] eb 71 [2] d6 }

  condition:
    any of them
}