rule TTP_XOR_MULT_DOSStub_c1a3 {
  strings:
    $key_c1a3 = { 95 cb [2] e1 d3 [2] a6 d1 [2] e1 c0 [2] af cc [2] a3 c6 [2] b4 cd [2] af 83 [2] 92 }

  condition:
    any of them
}