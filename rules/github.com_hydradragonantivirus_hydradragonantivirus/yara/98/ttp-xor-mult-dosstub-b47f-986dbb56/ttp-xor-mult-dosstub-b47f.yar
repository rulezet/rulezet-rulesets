rule TTP_XOR_MULT_DOSStub_b47f {
  strings:
    $key_b47f = { e0 17 [2] 94 0f [2] d3 0d [2] 94 1c [2] da 10 [2] d6 1a [2] c1 11 [2] da 5f [2] e7 }

  condition:
    any of them
}