rule TTP_XOR_MULT_DOSStub_a2b0 {
  strings:
    $key_a2b0 = { f6 d8 [2] 82 c0 [2] c5 c2 [2] 82 d3 [2] cc df [2] c0 d5 [2] d7 de [2] cc 90 [2] f1 }

  condition:
    any of them
}