rule TTP_XOR_MULT_DOSStub_b146 {
  strings:
    $key_b146 = { e5 2e [2] 91 36 [2] d6 34 [2] 91 25 [2] df 29 [2] d3 23 [2] c4 28 [2] df 66 [2] e2 }

  condition:
    any of them
}