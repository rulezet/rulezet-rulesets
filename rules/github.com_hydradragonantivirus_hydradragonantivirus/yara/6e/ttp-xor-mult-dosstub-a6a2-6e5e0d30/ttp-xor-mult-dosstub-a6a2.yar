rule TTP_XOR_MULT_DOSStub_a6a2 {
  strings:
    $key_a6a2 = { f2 ca [2] 86 d2 [2] c1 d0 [2] 86 c1 [2] c8 cd [2] c4 c7 [2] d3 cc [2] c8 82 [2] f5 }

  condition:
    any of them
}