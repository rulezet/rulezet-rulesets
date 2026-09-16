rule TTP_XOR_MULT_DOSStub_c4ac {
  strings:
    $key_c4ac = { 90 c4 [2] e4 dc [2] a3 de [2] e4 cf [2] aa c3 [2] a6 c9 [2] b1 c2 [2] aa 8c [2] 97 }

  condition:
    any of them
}