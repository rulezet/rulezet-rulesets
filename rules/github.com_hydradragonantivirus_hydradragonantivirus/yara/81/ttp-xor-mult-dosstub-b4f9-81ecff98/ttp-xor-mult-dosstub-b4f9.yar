rule TTP_XOR_MULT_DOSStub_b4f9 {
  strings:
    $key_b4f9 = { e0 91 [2] 94 89 [2] d3 8b [2] 94 9a [2] da 96 [2] d6 9c [2] c1 97 [2] da d9 [2] e7 }

  condition:
    any of them
}