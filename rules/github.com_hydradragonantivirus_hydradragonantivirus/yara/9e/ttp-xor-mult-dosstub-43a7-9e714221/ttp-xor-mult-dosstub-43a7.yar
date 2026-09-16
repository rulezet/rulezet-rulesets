rule TTP_XOR_MULT_DOSStub_43a7 {
  strings:
    $key_43a7 = { 17 cf [2] 63 d7 [2] 24 d5 [2] 63 c4 [2] 2d c8 [2] 21 c2 [2] 36 c9 [2] 2d 87 [2] 10 }

  condition:
    any of them
}