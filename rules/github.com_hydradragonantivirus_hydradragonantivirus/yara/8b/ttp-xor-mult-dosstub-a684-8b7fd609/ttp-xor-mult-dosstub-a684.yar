rule TTP_XOR_MULT_DOSStub_a684 {
  strings:
    $key_a684 = { f2 ec [2] 86 f4 [2] c1 f6 [2] 86 e7 [2] c8 eb [2] c4 e1 [2] d3 ea [2] c8 a4 [2] f5 }

  condition:
    any of them
}