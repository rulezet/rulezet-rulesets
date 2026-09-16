rule TTP_XOR_MULT_DOSStub_b4fd {
  strings:
    $key_b4fd = { e0 95 [2] 94 8d [2] d3 8f [2] 94 9e [2] da 92 [2] d6 98 [2] c1 93 [2] da dd [2] e7 }

  condition:
    any of them
}