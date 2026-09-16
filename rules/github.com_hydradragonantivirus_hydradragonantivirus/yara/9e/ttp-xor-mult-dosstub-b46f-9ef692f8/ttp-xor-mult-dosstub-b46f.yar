rule TTP_XOR_MULT_DOSStub_b46f {
  strings:
    $key_b46f = { e0 07 [2] 94 1f [2] d3 1d [2] 94 0c [2] da 00 [2] d6 0a [2] c1 01 [2] da 4f [2] e7 }

  condition:
    any of them
}