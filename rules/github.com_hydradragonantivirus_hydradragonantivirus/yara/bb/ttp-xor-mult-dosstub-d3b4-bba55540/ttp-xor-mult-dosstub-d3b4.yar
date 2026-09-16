rule TTP_XOR_MULT_DOSStub_d3b4 {
  strings:
    $key_d3b4 = { 87 dc [2] f3 c4 [2] b4 c6 [2] f3 d7 [2] bd db [2] b1 d1 [2] a6 da [2] bd 94 [2] 80 }

  condition:
    any of them
}