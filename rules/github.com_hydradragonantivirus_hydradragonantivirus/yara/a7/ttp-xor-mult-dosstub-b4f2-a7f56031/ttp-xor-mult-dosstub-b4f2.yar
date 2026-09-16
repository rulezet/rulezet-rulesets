rule TTP_XOR_MULT_DOSStub_b4f2 {
  strings:
    $key_b4f2 = { e0 9a [2] 94 82 [2] d3 80 [2] 94 91 [2] da 9d [2] d6 97 [2] c1 9c [2] da d2 [2] e7 }

  condition:
    any of them
}