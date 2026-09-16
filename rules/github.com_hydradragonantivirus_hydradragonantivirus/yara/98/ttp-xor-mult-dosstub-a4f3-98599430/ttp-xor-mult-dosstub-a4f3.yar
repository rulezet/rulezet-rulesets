rule TTP_XOR_MULT_DOSStub_a4f3 {
  strings:
    $key_a4f3 = { f0 9b [2] 84 83 [2] c3 81 [2] 84 90 [2] ca 9c [2] c6 96 [2] d1 9d [2] ca d3 [2] f7 }

  condition:
    any of them
}