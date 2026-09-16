rule TTP_XOR_MULT_DOSStub_a4a3 {
  strings:
    $key_a4a3 = { f0 cb [2] 84 d3 [2] c3 d1 [2] 84 c0 [2] ca cc [2] c6 c6 [2] d1 cd [2] ca 83 [2] f7 }

  condition:
    any of them
}