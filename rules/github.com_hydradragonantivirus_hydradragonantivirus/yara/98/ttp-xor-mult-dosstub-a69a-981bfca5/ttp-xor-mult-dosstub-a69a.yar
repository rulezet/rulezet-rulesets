rule TTP_XOR_MULT_DOSStub_a69a {
  strings:
    $key_a69a = { f2 f2 [2] 86 ea [2] c1 e8 [2] 86 f9 [2] c8 f5 [2] c4 ff [2] d3 f4 [2] c8 ba [2] f5 }

  condition:
    any of them
}