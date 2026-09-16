rule TTP_XOR_MULT_DOSStub_b3ea {
  strings:
    $key_b3ea = { e7 82 [2] 93 9a [2] d4 98 [2] 93 89 [2] dd 85 [2] d1 8f [2] c6 84 [2] dd ca [2] e0 }

  condition:
    any of them
}