rule TTP_XOR_MULT_DOSStub_c4a4 {
  strings:
    $key_c4a4 = { 90 cc [2] e4 d4 [2] a3 d6 [2] e4 c7 [2] aa cb [2] a6 c1 [2] b1 ca [2] aa 84 [2] 97 }

  condition:
    any of them
}