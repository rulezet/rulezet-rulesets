rule TTP_XOR_MULT_DOSStub_c6a3 {
  strings:
    $key_c6a3 = { 92 cb [2] e6 d3 [2] a1 d1 [2] e6 c0 [2] a8 cc [2] a4 c6 [2] b3 cd [2] a8 83 [2] 95 }

  condition:
    any of them
}