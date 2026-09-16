rule TTP_XOR_MULT_DOSStub_b4e8 {
  strings:
    $key_b4e8 = { e0 80 [2] 94 98 [2] d3 9a [2] 94 8b [2] da 87 [2] d6 8d [2] c1 86 [2] da c8 [2] e7 }

  condition:
    any of them
}