rule TTP_XOR_MULT_DOSStub_b473 {
  strings:
    $key_b473 = { e0 1b [2] 94 03 [2] d3 01 [2] 94 10 [2] da 1c [2] d6 16 [2] c1 1d [2] da 53 [2] e7 }

  condition:
    any of them
}