rule TTP_XOR_MULT_DOSStub_b4ae {
  strings:
    $key_b4ae = { e0 c6 [2] 94 de [2] d3 dc [2] 94 cd [2] da c1 [2] d6 cb [2] c1 c0 [2] da 8e [2] e7 }

  condition:
    any of them
}