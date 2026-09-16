rule TTP_XOR_MULT_DOSStub_879a {
  strings:
    $key_879a = { d3 f2 [2] a7 ea [2] e0 e8 [2] a7 f9 [2] e9 f5 [2] e5 ff [2] f2 f4 [2] e9 ba [2] d4 }

  condition:
    any of them
}