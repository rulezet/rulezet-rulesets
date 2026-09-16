rule TTP_XOR_MULT_DOSStub_51a7 {
  strings:
    $key_51a7 = { 05 cf [2] 71 d7 [2] 36 d5 [2] 71 c4 [2] 3f c8 [2] 33 c2 [2] 24 c9 [2] 3f 87 [2] 02 }

  condition:
    any of them
}