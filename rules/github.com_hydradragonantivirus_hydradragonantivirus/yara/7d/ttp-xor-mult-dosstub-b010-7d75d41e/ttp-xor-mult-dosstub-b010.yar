rule TTP_XOR_MULT_DOSStub_b010 {
  strings:
    $key_b010 = { e4 78 [2] 90 60 [2] d7 62 [2] 90 73 [2] de 7f [2] d2 75 [2] c5 7e [2] de 30 [2] e3 }

  condition:
    any of them
}