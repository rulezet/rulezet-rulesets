rule TTP_XOR_MULT_DOSStub_d7a3 {
  strings:
    $key_d7a3 = { 83 cb [2] f7 d3 [2] b0 d1 [2] f7 c0 [2] b9 cc [2] b5 c6 [2] a2 cd [2] b9 83 [2] 84 }

  condition:
    any of them
}