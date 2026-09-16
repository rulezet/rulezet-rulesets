rule TTP_XOR_MULT_DOSStub_6da7 {
  strings:
    $key_6da7 = { 39 cf [2] 4d d7 [2] 0a d5 [2] 4d c4 [2] 03 c8 [2] 0f c2 [2] 18 c9 [2] 03 87 [2] 3e }

  condition:
    any of them
}