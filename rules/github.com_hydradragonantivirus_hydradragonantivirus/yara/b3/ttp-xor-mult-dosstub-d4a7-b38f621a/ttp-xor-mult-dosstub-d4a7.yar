rule TTP_XOR_MULT_DOSStub_d4a7 {
  strings:
    $key_d4a7 = { 80 cf [2] f4 d7 [2] b3 d5 [2] f4 c4 [2] ba c8 [2] b6 c2 [2] a1 c9 [2] ba 87 [2] 87 }

  condition:
    any of them
}