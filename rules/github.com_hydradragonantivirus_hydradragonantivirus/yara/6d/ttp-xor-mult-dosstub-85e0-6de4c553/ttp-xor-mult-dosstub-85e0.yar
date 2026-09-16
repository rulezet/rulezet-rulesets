rule TTP_XOR_MULT_DOSStub_85e0 {
  strings:
    $key_85e0 = { d1 88 [2] a5 90 [2] e2 92 [2] a5 83 [2] eb 8f [2] e7 85 [2] f0 8e [2] eb c0 [2] d6 }

  condition:
    any of them
}