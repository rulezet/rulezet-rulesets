rule TTP_XOR_MULT_DOSStub_b49c {
  strings:
    $key_b49c = { e0 f4 [2] 94 ec [2] d3 ee [2] 94 ff [2] da f3 [2] d6 f9 [2] c1 f2 [2] da bc [2] e7 }

  condition:
    any of them
}