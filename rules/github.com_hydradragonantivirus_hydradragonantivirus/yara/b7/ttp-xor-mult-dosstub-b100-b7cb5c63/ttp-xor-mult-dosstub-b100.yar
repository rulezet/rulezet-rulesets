rule TTP_XOR_MULT_DOSStub_b100 {
  strings:
    $key_b100 = { e5 68 [2] 91 70 [2] d6 72 [2] 91 63 [2] df 6f [2] d3 65 [2] c4 6e [2] df 20 [2] e2 }

  condition:
    any of them
}