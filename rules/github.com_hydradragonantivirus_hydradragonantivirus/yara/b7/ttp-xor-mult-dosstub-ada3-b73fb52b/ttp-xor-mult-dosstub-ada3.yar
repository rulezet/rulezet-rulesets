rule TTP_XOR_MULT_DOSStub_ada3 {
  strings:
    $key_ada3 = { f9 cb [2] 8d d3 [2] ca d1 [2] 8d c0 [2] c3 cc [2] cf c6 [2] d8 cd [2] c3 83 [2] fe }

  condition:
    any of them
}