rule TTP_XOR_MULT_DOSStub_ada5 {
  strings:
    $key_ada5 = { f9 cd [2] 8d d5 [2] ca d7 [2] 8d c6 [2] c3 ca [2] cf c0 [2] d8 cb [2] c3 85 [2] fe }

  condition:
    any of them
}