rule TTP_XOR_MULT_DOSStub_c4a2 {
  strings:
    $key_c4a2 = { 90 ca [2] e4 d2 [2] a3 d0 [2] e4 c1 [2] aa cd [2] a6 c7 [2] b1 cc [2] aa 82 [2] 97 }

  condition:
    any of them
}