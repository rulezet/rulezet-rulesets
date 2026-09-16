rule TTP_XOR_MULT_DOSStub_b4e3 {
  strings:
    $key_b4e3 = { e0 8b [2] 94 93 [2] d3 91 [2] 94 80 [2] da 8c [2] d6 86 [2] c1 8d [2] da c3 [2] e7 }

  condition:
    any of them
}