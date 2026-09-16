rule TTP_XOR_MULT_DOSStub_a69c {
  strings:
    $key_a69c = { f2 f4 [2] 86 ec [2] c1 ee [2] 86 ff [2] c8 f3 [2] c4 f9 [2] d3 f2 [2] c8 bc [2] f5 }

  condition:
    any of them
}