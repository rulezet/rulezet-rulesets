rule TTP_XOR_MULT_DOSStub_d1a3 {
  strings:
    $key_d1a3 = { 85 cb [2] f1 d3 [2] b6 d1 [2] f1 c0 [2] bf cc [2] b3 c6 [2] a4 cd [2] bf 83 [2] 82 }

  condition:
    any of them
}