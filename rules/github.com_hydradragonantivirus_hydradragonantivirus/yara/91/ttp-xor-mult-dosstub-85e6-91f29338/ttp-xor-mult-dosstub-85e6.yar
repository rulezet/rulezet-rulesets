rule TTP_XOR_MULT_DOSStub_85e6 {
  strings:
    $key_85e6 = { d1 8e [2] a5 96 [2] e2 94 [2] a5 85 [2] eb 89 [2] e7 83 [2] f0 88 [2] eb c6 [2] d6 }

  condition:
    any of them
}