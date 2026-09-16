rule TTP_XOR_MULT_DOSStub_b39c {
  strings:
    $key_b39c = { e7 f4 [2] 93 ec [2] d4 ee [2] 93 ff [2] dd f3 [2] d1 f9 [2] c6 f2 [2] dd bc [2] e0 }

  condition:
    any of them
}