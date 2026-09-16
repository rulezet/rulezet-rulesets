rule TTP_XOR_MULT_DOSStub_ada7 {
  strings:
    $key_ada7 = { f9 cf [2] 8d d7 [2] ca d5 [2] 8d c4 [2] c3 c8 [2] cf c2 [2] d8 c9 [2] c3 87 [2] fe }

  condition:
    any of them
}