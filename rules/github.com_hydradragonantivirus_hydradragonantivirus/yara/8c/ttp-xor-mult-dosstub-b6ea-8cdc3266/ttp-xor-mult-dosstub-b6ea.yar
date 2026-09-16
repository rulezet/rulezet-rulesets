rule TTP_XOR_MULT_DOSStub_b6ea {
  strings:
    $key_b6ea = { e2 82 [2] 96 9a [2] d1 98 [2] 96 89 [2] d8 85 [2] d4 8f [2] c3 84 [2] d8 ca [2] e5 }

  condition:
    any of them
}