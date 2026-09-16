rule TTP_XOR_MULT_DOSStub_b111 {
  strings:
    $key_b111 = { e5 79 [2] 91 61 [2] d6 63 [2] 91 72 [2] df 7e [2] d3 74 [2] c4 7f [2] df 31 [2] e2 }

  condition:
    any of them
}