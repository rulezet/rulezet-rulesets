rule TTP_XOR_MULT_DOSStub_b4fc {
  strings:
    $key_b4fc = { e0 94 [2] 94 8c [2] d3 8e [2] 94 9f [2] da 93 [2] d6 99 [2] c1 92 [2] da dc [2] e7 }

  condition:
    any of them
}