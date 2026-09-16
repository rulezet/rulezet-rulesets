rule TTP_XOR_MULT_DOSStub_b140 {
  strings:
    $key_b140 = { e5 28 [2] 91 30 [2] d6 32 [2] 91 23 [2] df 2f [2] d3 25 [2] c4 2e [2] df 60 [2] e2 }

  condition:
    any of them
}