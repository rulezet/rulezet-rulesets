rule TTP_XOR_MULT_DOSStub_b137 {
  strings:
    $key_b137 = { e5 5f [2] 91 47 [2] d6 45 [2] 91 54 [2] df 58 [2] d3 52 [2] c4 59 [2] df 17 [2] e2 }

  condition:
    any of them
}