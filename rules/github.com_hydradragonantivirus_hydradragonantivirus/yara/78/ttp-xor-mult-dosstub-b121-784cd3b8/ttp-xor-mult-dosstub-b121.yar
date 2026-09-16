rule TTP_XOR_MULT_DOSStub_b121 {
  strings:
    $key_b121 = { e5 49 [2] 91 51 [2] d6 53 [2] 91 42 [2] df 4e [2] d3 44 [2] c4 4f [2] df 01 [2] e2 }

  condition:
    any of them
}