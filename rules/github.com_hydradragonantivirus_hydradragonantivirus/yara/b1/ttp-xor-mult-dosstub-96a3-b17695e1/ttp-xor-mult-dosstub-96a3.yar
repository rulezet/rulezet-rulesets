rule TTP_XOR_MULT_DOSStub_96a3 {
  strings:
    $key_96a3 = { c2 cb [2] b6 d3 [2] f1 d1 [2] b6 c0 [2] f8 cc [2] f4 c6 [2] e3 cd [2] f8 83 [2] c5 }

  condition:
    any of them
}