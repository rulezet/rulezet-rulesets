rule TTP_XOR_MULT_DOSStub_8565 {
  strings:
    $key_8565 = { d1 0d [2] a5 15 [2] e2 17 [2] a5 06 [2] eb 0a [2] e7 00 [2] f0 0b [2] eb 45 [2] d6 }

  condition:
    any of them
}