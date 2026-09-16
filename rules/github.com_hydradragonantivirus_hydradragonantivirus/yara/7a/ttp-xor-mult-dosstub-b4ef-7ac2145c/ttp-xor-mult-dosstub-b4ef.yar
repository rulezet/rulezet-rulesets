rule TTP_XOR_MULT_DOSStub_b4ef {
  strings:
    $key_b4ef = { e0 87 [2] 94 9f [2] d3 9d [2] 94 8c [2] da 80 [2] d6 8a [2] c1 81 [2] da cf [2] e7 }

  condition:
    any of them
}