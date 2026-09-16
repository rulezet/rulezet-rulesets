rule TTP_XOR_MULT_DOSStub_c4a1 {
  strings:
    $key_c4a1 = { 90 c9 [2] e4 d1 [2] a3 d3 [2] e4 c2 [2] aa ce [2] a6 c4 [2] b1 cf [2] aa 81 [2] 97 }

  condition:
    any of them
}