rule TTP_XOR_MULT_DOSStub_3da7 {
  strings:
    $key_3da7 = { 69 cf [2] 1d d7 [2] 5a d5 [2] 1d c4 [2] 53 c8 [2] 5f c2 [2] 48 c9 [2] 53 87 [2] 6e }

  condition:
    any of them
}