rule TTP_XOR_MULT_DOSStub_b136 {
  strings:
    $key_b136 = { e5 5e [2] 91 46 [2] d6 44 [2] 91 55 [2] df 59 [2] d3 53 [2] c4 58 [2] df 16 [2] e2 }

  condition:
    any of them
}