rule TTP_XOR_MULT_DOSStub_855b {
  strings:
    $key_855b = { d1 33 [2] a5 2b [2] e2 29 [2] a5 38 [2] eb 34 [2] e7 3e [2] f0 35 [2] eb 7b [2] d6 }

  condition:
    any of them
}