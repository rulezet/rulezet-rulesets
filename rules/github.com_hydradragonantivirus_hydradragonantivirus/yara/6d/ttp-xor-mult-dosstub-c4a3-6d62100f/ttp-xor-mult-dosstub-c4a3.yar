rule TTP_XOR_MULT_DOSStub_c4a3 {
  strings:
    $key_c4a3 = { 90 cb [2] e4 d3 [2] a3 d1 [2] e4 c0 [2] aa cc [2] a6 c6 [2] b1 cd [2] aa 83 [2] 97 }

  condition:
    any of them
}