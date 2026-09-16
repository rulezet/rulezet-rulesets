rule TTP_XOR_MULT_DOSStub_b151 {
  strings:
    $key_b151 = { e5 39 [2] 91 21 [2] d6 23 [2] 91 32 [2] df 3e [2] d3 34 [2] c4 3f [2] df 71 [2] e2 }

  condition:
    any of them
}