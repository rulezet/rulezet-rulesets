rule TTP_XOR_MULT_DOSStub_b142 {
  strings:
    $key_b142 = { e5 2a [2] 91 32 [2] d6 30 [2] 91 21 [2] df 2d [2] d3 27 [2] c4 2c [2] df 62 [2] e2 }

  condition:
    any of them
}