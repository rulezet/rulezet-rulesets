rule TTP_XOR_MULT_DOSStub_c4a7 {
  strings:
    $key_c4a7 = { 90 cf [2] e4 d7 [2] a3 d5 [2] e4 c4 [2] aa c8 [2] a6 c2 [2] b1 c9 [2] aa 87 [2] 97 }

  condition:
    any of them
}