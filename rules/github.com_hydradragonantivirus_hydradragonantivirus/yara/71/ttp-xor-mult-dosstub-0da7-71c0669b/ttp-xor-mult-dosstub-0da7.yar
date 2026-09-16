rule TTP_XOR_MULT_DOSStub_0da7 {
  strings:
    $key_0da7 = { 59 cf [2] 2d d7 [2] 6a d5 [2] 2d c4 [2] 63 c8 [2] 6f c2 [2] 78 c9 [2] 63 87 [2] 5e }

  condition:
    any of them
}