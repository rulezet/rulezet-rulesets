rule TTP_XOR_MULT_DOSStub_b0ea {
  strings:
    $key_b0ea = { e4 82 [2] 90 9a [2] d7 98 [2] 90 89 [2] de 85 [2] d2 8f [2] c5 84 [2] de ca [2] e3 }

  condition:
    any of them
}