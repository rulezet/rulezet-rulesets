rule TTP_XOR_MULT_DOSStub_b412 {
  strings:
    $key_b412 = { e0 7a [2] 94 62 [2] d3 60 [2] 94 71 [2] da 7d [2] d6 77 [2] c1 7c [2] da 32 [2] e7 }

  condition:
    any of them
}