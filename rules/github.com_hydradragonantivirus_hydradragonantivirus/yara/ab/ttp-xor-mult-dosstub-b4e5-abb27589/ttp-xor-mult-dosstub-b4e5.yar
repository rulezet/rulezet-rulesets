rule TTP_XOR_MULT_DOSStub_b4e5 {
  strings:
    $key_b4e5 = { e0 8d [2] 94 95 [2] d3 97 [2] 94 86 [2] da 8a [2] d6 80 [2] c1 8b [2] da c5 [2] e7 }

  condition:
    any of them
}