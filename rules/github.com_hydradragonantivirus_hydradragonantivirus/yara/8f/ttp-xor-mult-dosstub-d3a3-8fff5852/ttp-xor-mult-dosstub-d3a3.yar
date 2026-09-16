rule TTP_XOR_MULT_DOSStub_d3a3 {
  strings:
    $key_d3a3 = { 87 cb [2] f3 d3 [2] b4 d1 [2] f3 c0 [2] bd cc [2] b1 c6 [2] a6 cd [2] bd 83 [2] 80 }

  condition:
    any of them
}