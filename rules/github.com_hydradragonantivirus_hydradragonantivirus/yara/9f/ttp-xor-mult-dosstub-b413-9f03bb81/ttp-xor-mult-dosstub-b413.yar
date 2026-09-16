rule TTP_XOR_MULT_DOSStub_b413 {
  strings:
    $key_b413 = { e0 7b [2] 94 63 [2] d3 61 [2] 94 70 [2] da 7c [2] d6 76 [2] c1 7d [2] da 33 [2] e7 }

  condition:
    any of them
}