rule TTP_XOR_MULT_DOSStub_b147 {
  strings:
    $key_b147 = { e5 2f [2] 91 37 [2] d6 35 [2] 91 24 [2] df 28 [2] d3 22 [2] c4 29 [2] df 67 [2] e2 }

  condition:
    any of them
}