rule TTP_XOR_MULT_DOSStub_c7a3 {
  strings:
    $key_c7a3 = { 93 cb [2] e7 d3 [2] a0 d1 [2] e7 c0 [2] a9 cc [2] a5 c6 [2] b2 cd [2] a9 83 [2] 94 }

  condition:
    any of them
}