rule TTP_XOR_MULT_DOSStub_2da7 {
  strings:
    $key_2da7 = { 79 cf [2] 0d d7 [2] 4a d5 [2] 0d c4 [2] 43 c8 [2] 4f c2 [2] 58 c9 [2] 43 87 [2] 7e }

  condition:
    any of them
}