rule TTP_XOR_MULT_DOSStub_b160 {
  strings:
    $key_b160 = { e5 08 [2] 91 10 [2] d6 12 [2] 91 03 [2] df 0f [2] d3 05 [2] c4 0e [2] df 40 [2] e2 }

  condition:
    any of them
}