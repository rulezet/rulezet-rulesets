rule TTP_XOR_MULT_DOSStub_a2a3 {
  strings:
    $key_a2a3 = { f6 cb [2] 82 d3 [2] c5 d1 [2] 82 c0 [2] cc cc [2] c0 c6 [2] d7 cd [2] cc 83 [2] f1 }

  condition:
    any of them
}