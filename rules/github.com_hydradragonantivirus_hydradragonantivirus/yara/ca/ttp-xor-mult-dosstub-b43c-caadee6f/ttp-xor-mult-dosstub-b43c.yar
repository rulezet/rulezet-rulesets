rule TTP_XOR_MULT_DOSStub_b43c {
  strings:
    $key_b43c = { e0 54 [2] 94 4c [2] d3 4e [2] 94 5f [2] da 53 [2] d6 59 [2] c1 52 [2] da 1c [2] e7 }

  condition:
    any of them
}