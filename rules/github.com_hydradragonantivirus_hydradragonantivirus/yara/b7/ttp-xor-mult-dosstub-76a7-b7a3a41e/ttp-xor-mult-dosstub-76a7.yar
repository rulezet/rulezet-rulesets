rule TTP_XOR_MULT_DOSStub_76a7 {
  strings:
    $key_76a7 = { 22 cf [2] 56 d7 [2] 11 d5 [2] 56 c4 [2] 18 c8 [2] 14 c2 [2] 03 c9 [2] 18 87 [2] 25 }

  condition:
    any of them
}