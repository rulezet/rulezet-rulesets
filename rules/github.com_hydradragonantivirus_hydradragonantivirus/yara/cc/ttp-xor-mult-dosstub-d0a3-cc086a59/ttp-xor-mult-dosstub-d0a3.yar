rule TTP_XOR_MULT_DOSStub_d0a3 {
  strings:
    $key_d0a3 = { 84 cb [2] f0 d3 [2] b7 d1 [2] f0 c0 [2] be cc [2] b2 c6 [2] a5 cd [2] be 83 [2] 83 }

  condition:
    any of them
}