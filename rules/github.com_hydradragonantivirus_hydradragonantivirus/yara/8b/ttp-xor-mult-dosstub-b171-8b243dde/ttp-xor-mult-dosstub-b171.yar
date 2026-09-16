rule TTP_XOR_MULT_DOSStub_b171 {
  strings:
    $key_b171 = { e5 19 [2] 91 01 [2] d6 03 [2] 91 12 [2] df 1e [2] d3 14 [2] c4 1f [2] df 51 [2] e2 }

  condition:
    any of them
}