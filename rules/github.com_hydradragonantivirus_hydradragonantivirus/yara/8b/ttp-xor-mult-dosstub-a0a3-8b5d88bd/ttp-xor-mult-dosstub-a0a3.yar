rule TTP_XOR_MULT_DOSStub_a0a3 {
  strings:
    $key_a0a3 = { f4 cb [2] 80 d3 [2] c7 d1 [2] 80 c0 [2] ce cc [2] c2 c6 [2] d5 cd [2] ce 83 [2] f3 }

  condition:
    any of them
}