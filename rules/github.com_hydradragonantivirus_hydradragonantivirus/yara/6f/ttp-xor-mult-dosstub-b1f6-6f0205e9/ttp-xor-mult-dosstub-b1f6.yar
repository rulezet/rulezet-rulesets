rule TTP_XOR_MULT_DOSStub_b1f6 {
  strings:
    $key_b1f6 = { e5 9e [2] 91 86 [2] d6 84 [2] 91 95 [2] df 99 [2] d3 93 [2] c4 98 [2] df d6 [2] e2 }

  condition:
    any of them
}